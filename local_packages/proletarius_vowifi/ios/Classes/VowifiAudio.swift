import AVFoundation
import Foundation

/// Graph mutations and conversion live on `queue`; no Go call runs on the
/// audio render thread. Pending capture/playback work is explicitly bounded.
final class VowifiAudio {
    private let queue = DispatchQueue(label: "proletarius.vowifi.audio", qos: .userInteractive)
    private let writer = DispatchQueue(label: "proletarius.vowifi.microphone", qos: .userInteractive)
    private let lock = NSLock()
    private var epoch: UInt64 = 0
    private var running = false
    private var muted = false
    private var captures = 0
    private var playbacks = 0
    private var writes = 0
    private var engine: AVAudioEngine?
    private var player: AVAudioPlayerNode?
    private var inputConverter: AVAudioConverter?
    private var outputConverter: AVAudioConverter?
    private var outputFormat: AVAudioFormat?
    private var captureRemainder = Data()
    private var capturedFrames = 0
    private var scheduledFrames = 0
    private var transmit: ((Data) throws -> Void)?
    private var reportError: ((Error) -> Void)?
    private var observations: [NSObjectProtocol] = []
    private var sessionActive = false
    private var interrupted = false
    private var wantsAudio = false
    private var graphRoute: String?
    private var pendingRouteChange: DispatchWorkItem?
    private let pcm = AVAudioFormat(commonFormat: .pcmFormatInt16, sampleRate: 8_000,
                                   channels: 1, interleaved: true)!

    init(onError: @escaping (Error) -> Void) {
        reportError = onError
        let center = NotificationCenter.default
        observations.append(center.addObserver(forName: .AVAudioEngineConfigurationChange,
                                               object: nil, queue: nil) { [weak self] notification in
            guard let changed = notification.object as? AVAudioEngine else { return }
            // Do not retain the notifying engine across queues. Configuration
            // notifications can be emitted during graph teardown; retaining it
            // here makes its final release occur in a stale queued closure.
            let changedID = ObjectIdentifier(changed)
            self?.queue.async { [weak self] in
                guard let self = self, let current = self.engine,
                      ObjectIdentifier(current) == changedID,
                      self.sessionActive, self.wantsAudio, !self.interrupted else { return }
                self.pendingRouteChange?.cancel()
                let work = DispatchWorkItem { [weak self] in self?.rebuildIfNeeded() }
                self.pendingRouteChange = work
                self.queue.asyncAfter(deadline: .now() + 0.3, execute: work)
            }
        })
        observations.append(center.addObserver(forName: AVAudioSession.routeChangeNotification,
                                               object: nil, queue: nil) { [weak self] _ in
            self?.queue.async { [weak self] in
                guard let self = self else { return }
                self.pendingRouteChange?.cancel()
                let work = DispatchWorkItem { [weak self] in self?.rebuildIfNeeded() }
                self.pendingRouteChange = work
                self.queue.asyncAfter(deadline: .now() + 0.3, execute: work)
            }
        })
        observations.append(center.addObserver(forName: AVAudioSession.interruptionNotification,
                                               object: nil, queue: nil) { [weak self] notification in
            let type = (notification.userInfo?[AVAudioSessionInterruptionTypeKey] as? NSNumber)?.uintValue
            let options = (notification.userInfo?[AVAudioSessionInterruptionOptionKey] as? NSNumber)?.uintValue ?? 0
            self?.queue.async { [weak self] in
                guard let self = self else { return }
                if type == AVAudioSession.InterruptionType.began.rawValue {
                    self.interrupted = true
                    self.stopGraph()
                } else if type == AVAudioSession.InterruptionType.ended.rawValue {
                    self.interrupted = false
                    // Resume only while CallKit still grants audio ownership.
                    // Never activate a session that CallKit has deactivated.
                    if AVAudioSession.InterruptionOptions(rawValue: options).contains(.shouldResume), self.sessionActive {
                        self.rebuildIfNeeded()
                    }
                }
            }
        })
        observations.append(center.addObserver(forName: AVAudioSession.mediaServicesWereResetNotification,
                                               object: nil, queue: nil) { [weak self] _ in
            self?.queue.async { [weak self] in
                guard let self = self else { return }
                self.sessionActive = false
                self.stopGraph()
                self.fail(NSError(domain: "VowifiAudio", code: 3,
                                  userInfo: [NSLocalizedDescriptionKey: "Audio services restarted. End the call and try again."]))
            }
        })
    }

    deinit { observations.forEach(NotificationCenter.default.removeObserver) }

    static func configureSession() throws {
        let session = AVAudioSession.sharedInstance()
        // HFP supports simultaneous microphone/playback. Do not force the
        // loudspeaker or A2DP, which would disrupt receiver/headset routing.
        try session.setCategory(.playAndRecord, mode: .voiceChat, options: [.allowBluetoothHFP])
        try session.setPreferredSampleRate(48_000)
        try session.setPreferredIOBufferDuration(0.02)
    }

    func attach(transmit: @escaping (Data) throws -> Void) {
        queue.async {
            self.transmit = transmit
            if self.sessionActive && self.wantsAudio { self.rebuildIfNeeded() }
        }
    }

    func activate() {
        queue.async {
            self.sessionActive = true
            self.interrupted = false
            NSLog("[VoWiFi audio] CallKit activated audio")
            self.rebuildIfNeeded()
        }
    }

    func deactivate() {
        queue.async {
            self.sessionActive = false
            NSLog("[VoWiFi audio] CallKit deactivated audio")
            self.stopGraph()
        }
    }

    func setMediaReady(_ ready: Bool) {
        queue.async {
            guard self.wantsAudio != ready else { return }
            self.wantsAudio = ready
            if ready { self.rebuildIfNeeded() } else { self.stopGraph() }
        }
    }

    func setMuted(_ value: Bool) {
        lock.lock(); muted = value; lock.unlock()
    }

    func controlState() -> [String: Any] {
        lock.lock(); let isMuted = muted; lock.unlock()
        let speaker = AVAudioSession.sharedInstance().currentRoute.outputs.contains { $0.portType == .builtInSpeaker }
        return ["muted": isMuted, "speaker": speaker]
    }

    func stop() {
        queue.async {
            self.wantsAudio = false
            self.sessionActive = false
            self.interrupted = false
            self.stopGraph()
            self.transmit = nil
            self.setMuted(false)
        }
    }

    func setSpeaker(_ enabled: Bool, completion: @escaping (Error?) -> Void) {
        queue.async {
            do {
                try AVAudioSession.sharedInstance().overrideOutputAudioPort(enabled ? .speaker : .none)
                DispatchQueue.main.async { completion(nil) }
            } catch { DispatchQueue.main.async { completion(error) } }
        }
    }

    private func reserve(_ capture: Bool) -> UInt64? {
        lock.lock(); defer { lock.unlock() }
        guard running else { return nil }
        if capture {
            guard captures < 3 else { return nil }
            captures += 1
        } else {
            guard playbacks < 8 else { return nil }
            playbacks += 1
        }
        return epoch
    }

    private func release(_ capture: Bool, epoch ticket: UInt64) {
        lock.lock(); defer { lock.unlock() }
        guard ticket == epoch else { return }
        if capture { captures = max(0, captures - 1) } else { playbacks = max(0, playbacks - 1) }
    }

    private func isCurrent(_ ticket: UInt64) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return running && epoch == ticket
    }

    private func rebuildIfNeeded() {
        let session = AVAudioSession.sharedInstance()
        let route = Self.routeIdentity(session)
        // Enabling voice processing emits route notifications itself. Rebuilding
        // an already-running graph for the same route creates a feedback loop
        // that repeatedly tears down the render thread during the call.
        if sessionActive, !interrupted, wantsAudio, transmit != nil,
           let graph = engine, graphRoute == route {
            if !graph.isRunning || player?.isPlaying != true {
                do {
                    // A configuration change invalidates scheduled buffers.
                    // Invalidate their tickets before flushing, otherwise the
                    // bounded playback queue can remain permanently full.
                    lock.lock()
                    epoch &+= 1
                    captures = 0; playbacks = 0; writes = 0
                    lock.unlock()
                    player?.stop()
                    inputConverter?.reset()
                    outputConverter?.reset()
                    captureRemainder.removeAll(keepingCapacity: true)
                    try graph.start()
                    player?.play()
                    NSLog("[VoWiFi audio] resumed existing graph")
                } catch { fail(error) }
            }
            return
        }
        stopGraph()
        guard sessionActive, !interrupted, wantsAudio, transmit != nil else { return }
        do {
            guard session.isInputAvailable, session.sampleRate > 0 else {
                throw NSError(domain: "VowifiAudio", code: 1,
                              userInfo: [NSLocalizedDescriptionKey: "No microphone audio route is available."])
            }
            let graph = AVAudioEngine()
            let input = graph.inputNode
            try input.setVoiceProcessingEnabled(true)
            let native = input.outputFormat(forBus: 0)
            guard native.sampleRate > 0, native.channelCount > 0,
                  let output = AVAudioFormat(commonFormat: .pcmFormatFloat32,
                                            sampleRate: session.sampleRate, channels: 1, interleaved: false),
                  let downsample = AVAudioConverter(from: native, to: pcm),
                  let upsample = AVAudioConverter(from: pcm, to: output) else {
                throw NSError(domain: "VowifiAudio", code: 2,
                              userInfo: [NSLocalizedDescriptionKey: "The current audio route cannot convert 8 kHz voice audio."])
            }
            let playback = AVAudioPlayerNode()
            graph.attach(playback)
            graph.connect(playback, to: graph.mainMixerNode, format: output)
            engine = graph
            player = playback
            outputFormat = output
            inputConverter = downsample
            outputConverter = upsample
            lock.lock(); running = true; lock.unlock()
            input.installTap(onBus: 0, bufferSize: 960, format: native) { [weak self] buffer, _ in
                guard let self = self, let ticket = self.reserve(true) else { return }
                // The tap's buffer is reused by AVAudioEngine after return.
                guard let copy = Self.copy(buffer) else { self.release(true, epoch: ticket); return }
                self.queue.async {
                    defer { self.release(true, epoch: ticket) }
                    guard self.isCurrent(ticket) else { return }
                    self.capture(copy, epoch: ticket)
                }
            }
            graph.prepare()
            try graph.start()
            playback.play()
            graphRoute = Self.routeIdentity(session)
            NSLog("[VoWiFi audio] graph started input=%@ output=%@ rate=%.0f", session.currentRoute.inputs.map { $0.portType.rawValue }.joined(separator: ","), session.currentRoute.outputs.map { $0.portType.rawValue }.joined(separator: ","), session.sampleRate)
        } catch {
            stopGraph()
            fail(error)
        }
    }

    private func stopGraph() {
        pendingRouteChange?.cancel()
        pendingRouteChange = nil
        lock.lock()
        running = false
        epoch &+= 1
        captures = 0; playbacks = 0; writes = 0
        lock.unlock()
        if let graph = engine {
            graph.stop()
            graph.inputNode.removeTap(onBus: 0)
            player?.stop()
        }
        engine = nil; player = nil
        graphRoute = nil
        inputConverter = nil; outputConverter = nil; outputFormat = nil
        captureRemainder.removeAll(keepingCapacity: true)
        capturedFrames = 0
        scheduledFrames = 0
    }

    private static func routeIdentity(_ session: AVAudioSession) -> String {
        let inputs = session.currentRoute.inputs.map { $0.uid }.joined(separator: "|")
        let outputs = session.currentRoute.outputs.map { $0.uid }.joined(separator: "|")
        // VoiceProcessingIO changes channel counts and sample-rate reporting
        // during initialization without changing the physical audio route.
        return "\(inputs)>\(outputs)"
    }

    private static func copy(_ source: AVAudioPCMBuffer) -> AVAudioPCMBuffer? {
        guard let destination = AVAudioPCMBuffer(pcmFormat: source.format, frameCapacity: source.frameLength) else { return nil }
        destination.frameLength = source.frameLength
        let src = UnsafeMutableAudioBufferListPointer(UnsafeMutablePointer(mutating: source.audioBufferList))
        let dst = UnsafeMutableAudioBufferListPointer(destination.mutableAudioBufferList)
        for index in 0..<min(src.count, dst.count) {
            guard let from = src[index].mData, let to = dst[index].mData else { return nil }
            memcpy(to, from, min(Int(src[index].mDataByteSize), Int(dst[index].mDataByteSize)))
        }
        return destination
    }

    private func convert(_ input: AVAudioPCMBuffer, using converter: AVAudioConverter,
                         to format: AVAudioFormat) throws -> AVAudioPCMBuffer? {
        let capacity = AVAudioFrameCount(ceil(Double(input.frameLength) * format.sampleRate / input.format.sampleRate)) + 64
        guard let result = AVAudioPCMBuffer(pcmFormat: format, frameCapacity: capacity) else { return nil }
        var supplied = false
        var error: NSError?
        let status = converter.convert(to: result, error: &error) { _, outStatus in
            if supplied { outStatus.pointee = .noDataNow; return nil }
            supplied = true
            outStatus.pointee = .haveData
            return input
        }
        if let error = error { throw error }
        guard status != .error, result.frameLength > 0 else { return nil }
        return result
    }

    private func capture(_ buffer: AVAudioPCMBuffer, epoch ticket: UInt64) {
        guard let converter = inputConverter, let transmit = transmit else { return }
        do {
            guard let converted = try convert(buffer, using: converter, to: pcm),
                  let samples = converted.int16ChannelData?[0] else { return }
            lock.lock(); let silence = muted; lock.unlock()
            if silence {
                captureRemainder.append(Data(count: Int(converted.frameLength) * 2))
            } else {
                captureRemainder.append(Data(bytes: samples, count: Int(converted.frameLength) * 2))
            }
            while captureRemainder.count >= 320 {
                let frame = Data(captureRemainder.prefix(320))
                captureRemainder.removeFirst(320)
                lock.lock()
                let accepted = writes < 4 && ticket == epoch && running
                if accepted { writes += 1 }
                lock.unlock()
                guard accepted else { continue }
                capturedFrames += 1
                if capturedFrames == 1 || capturedFrames % 250 == 0 {
                    NSLog("[VoWiFi audio] microphone frames=%d muted=%@", capturedFrames, silence ? "yes" : "no")
                }
                writer.async {
                    defer {
                        self.lock.lock()
                        if self.epoch == ticket { self.writes = max(0, self.writes - 1) }
                        self.lock.unlock()
                    }
                    guard self.isCurrent(ticket) else { return }
                    do { try transmit(frame) } catch { self.fail(error) }
                }
            }
        } catch { fail(error) }
    }

    func receive(_ data: Data) {
        guard data.count == 320, let ticket = reserve(false) else { return }
        queue.async { [self] in
            guard self.isCurrent(ticket), let converter = self.outputConverter,
                  let format = self.outputFormat, let player = self.player,
                  let input = AVAudioPCMBuffer(pcmFormat: self.pcm, frameCapacity: 160),
                  let samples = input.int16ChannelData?[0] else {
                self.release(false, epoch: ticket); return
            }
            input.frameLength = 160
            data.withUnsafeBytes { bytes in
                if let address = bytes.baseAddress { memcpy(samples, address, 320) }
            }
            do {
                guard let output = try self.convert(input, using: converter, to: format) else {
                    self.release(false, epoch: ticket); return
                }
                player.scheduleBuffer(output, completionCallbackType: .dataConsumed) { [weak self] _ in
                    self?.release(false, epoch: ticket)
                }
                self.scheduledFrames += 1
                if self.scheduledFrames == 1 || self.scheduledFrames % 250 == 0 {
                    NSLog("[VoWiFi audio] playback scheduled frames=%d engineRunning=%@", self.scheduledFrames, self.engine?.isRunning == true ? "yes" : "no")
                }
            } catch {
                self.release(false, epoch: ticket)
                self.fail(error)
            }
        }
    }

    private func fail(_ error: Error) {
        NSLog("[VoWiFi audio] failure: %@", error.localizedDescription)
        DispatchQueue.main.async { [weak self] in self?.reportError?(error) }
    }
}
