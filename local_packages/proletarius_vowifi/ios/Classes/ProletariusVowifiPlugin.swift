import AVFoundation
import Flutter
import Foundation
import Mobilecore
import Network
import UIKit

private func bridgeError(_ message: String) -> NSError {
    NSError(domain: "ProletariusVoWiFi", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
}

private func jsonString(_ value: [String: Any]) -> String {
    guard let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]),
          let text = String(data: data, encoding: .utf8) else { return "{}" }
    return text
}

private final class PendingAPDU {
    let signal = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var outcome: Result<String, Error>?

    func complete(_ result: Result<String, Error>) {
        lock.lock()
        guard outcome == nil else { lock.unlock(); return }
        outcome = result
        lock.unlock()
        signal.signal()
    }

    func wait(seconds: TimeInterval = 30, timeoutMessage: String = "The SIM reader did not answer within 30 seconds.") throws -> String {
        if signal.wait(timeout: .now() + seconds) == .timedOut {
            complete(.failure(bridgeError(timeoutMessage)))
        }
        lock.lock(); let result = outcome; lock.unlock()
        return try (result ?? .failure(bridgeError("SIM request was cancelled."))).get()
    }
}

/// A new host is allocated for each engine, preventing callbacks from an old
/// reader generation from being delivered to a replacement session.
private final class VowifiHost: NSObject, MobilecoreHostProtocol {
    private let lock = NSLock()
    private var cancelled = false
    private var pending: [UUID: PendingAPDU] = [:]
    private var storage: [UUID: PendingAPDU] = [:]
    var exchange: ((String, @escaping (Any?) -> Void) -> Void)?
    var store: ((String, @escaping (Any?) -> Void) -> Void)?
    var event: ((String) -> Void)?

    func exchangeAPDUs(_ requestJSON: String?, error: NSErrorPointer) -> String {
        do { return try exchangeRequest(requestJSON) }
        catch let failure {
            error?.pointee = failure as NSError
            return ""
        }
    }

    private func exchangeRequest(_ requestJSON: String?) throws -> String {
        guard let requestJSON = requestJSON else { throw bridgeError("Missing SIM request.") }
        guard !Thread.isMainThread else { throw bridgeError("SIM exchange cannot block the UI thread.") }
        let request = PendingAPDU()
        let token = UUID()
        lock.lock()
        guard !cancelled, pending.count < 4 else {
            lock.unlock(); throw bridgeError("SIM session cancelled or request limit reached.")
        }
        pending[token] = request
        lock.unlock()
        defer { lock.lock(); pending.removeValue(forKey: token); lock.unlock() }
        DispatchQueue.main.async { [weak self] in
            guard let self = self, self.isPending(token), let exchange = self.exchange else {
                request.complete(.failure(bridgeError("SIM session was cancelled."))); return
            }
            exchange(requestJSON) { [weak self] reply in
                guard self?.isPending(token) == true else { return }
                if let json = reply as? String {
                    request.complete(.success(json))
                } else if let error = reply as? FlutterError {
                    request.complete(.failure(bridgeError(error.message ?? error.code)))
                } else {
                    request.complete(.failure(bridgeError("The SIM bridge returned an invalid reply.")))
                }
            }
        }
        return try request.wait()
    }

    func storeSMS(_ eventJSON: String?) throws {
        guard let eventJSON = eventJSON else { throw bridgeError("Missing SMS storage request.") }
        guard !Thread.isMainThread else { throw bridgeError("SMS storage cannot block the UI thread.") }
        let request = PendingAPDU()
        let token = UUID()
        lock.lock()
        guard !cancelled, storage.count < 8 else {
            lock.unlock(); throw bridgeError("SMS session cancelled or storage request limit reached.")
        }
        storage[token] = request
        lock.unlock()
        defer { lock.lock(); storage.removeValue(forKey: token); lock.unlock() }
        DispatchQueue.main.async { [weak self] in
            guard let self = self, self.isPending(token, isStorage: true), let store = self.store else {
                request.complete(.failure(bridgeError("SMS session was cancelled."))); return
            }
            store(eventJSON) { [weak self] reply in
                guard self?.isPending(token, isStorage: true) == true else { return }
                if let committed = reply as? Bool, committed {
                    request.complete(.success("{}"))
                } else if let error = reply as? FlutterError {
                    request.complete(.failure(bridgeError(error.message ?? error.code)))
                } else {
                    request.complete(.failure(bridgeError("SMS was not confirmed saved.")))
                }
            }
        }
        _ = try request.wait(seconds: 5, timeoutMessage: "SMS storage did not commit within 5 seconds.")
    }

    func onEvent(_ eventJSON: String?) {
        guard let eventJSON = eventJSON else { return }
        lock.lock(); let active = !cancelled; lock.unlock()
        guard active else { return }
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.lock.lock(); let active = !self.cancelled; self.lock.unlock()
            if active { self.event?(eventJSON) }
        }
    }

    private func isPending(_ token: UUID, isStorage: Bool = false) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return !cancelled && (isStorage ? storage[token] != nil : pending[token] != nil)
    }

    func cancel() {
        lock.lock()
        cancelled = true
        let requests = Array(pending.values) + Array(storage.values)
        pending.removeAll()
        storage.removeAll()
        lock.unlock()
        requests.forEach { $0.complete(.failure(bridgeError("SIM session was cancelled."))) }
    }
}

private final class VowifiRun {
    let recoveryID = UUID()
    let host = VowifiHost()
    let operations = DispatchGroup()
    let generation: Int64
    let cardOnly: Bool
    private let lock = NSLock()
    private var stopped = false
    private var engine: MobilecoreEngine?

    init(generation: Int64, cardOnly: Bool = false) {
        self.generation = generation
        self.cardOnly = cardOnly
    }

    var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return stopped }

    func attach(_ value: MobilecoreEngine) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard !stopped else { return false }
        engine = value
        return true
    }

    func snapshot() -> MobilecoreEngine? { lock.lock(); defer { lock.unlock() }; return engine }

    func cancel() {
        lock.lock(); stopped = true; lock.unlock()
        host.cancel()
    }
}

public final class ProletariusVowifiPlugin: NSObject, FlutterPlugin {
    private let channel: FlutterMethodChannel
    // The Go engine may ask for APDUs or persist SMS from a worker thread,
    // while Flutter start/stop and reader-generation changes run on main.
    // Guard only the cross-thread session identity; UI-facing state remains
    // owned by the main queue.
    private let sessionLock = NSLock()
    private let control = DispatchQueue(label: "proletarius.vowifi.control", qos: .userInitiated)
    private let cancellation = DispatchQueue(label: "proletarius.vowifi.cancel", qos: .userInitiated)
    private let callEnding = DispatchQueue(label: "proletarius.vowifi.call-ending", qos: .userInitiated)
    private var run: VowifiRun?
    private var retiringRun: VowifiRun?
    private var stopping = false
    private var pendingCommands = 0
    private var stopWaiters: [FlutterResult] = []
    private var detached = false
    private let diagnosticQueue = DispatchQueue(label: "nekokolpa.vowifi.diagnostics")
    private var lastDiagnosticState = ""
    private var cachedStatus = jsonString(["type": "status", "phase": "idle", "registered": false,
                                          "messaging_ready": false, "call_ready": false])
    private var observers: [NSObjectProtocol] = []
    private let pathMonitor = NWPathMonitor()
    private let pathQueue = DispatchQueue(label: "proletarius.vowifi.path")
    private var lastPath: NWPath?
    private var recovery = VowifiRecoveryPolicy()
    private var recoveryWork: DispatchWorkItem?
    private var recoveryScheduledTicket: VowifiRecoveryPolicy.Ticket?
    private lazy var audio: VowifiAudio = VowifiAudio { [weak self] error in
        guard let self = self else { return }
        self.emit(["type": "native_error", "source": "audio", "error": error.localizedDescription])
        if self.calls.hasCall {
            self.execute(["action": "hangup"]) { _ in }
            self.calls.endAll()
        }
    }
    private lazy var calls: VowifiCalls = VowifiCalls(audio: audio, execute: { [weak self] command, completion in
        guard let self = self else { completion(.failure(bridgeError("VoWiFi plugin detached."))); return }
        self.execute(command, completion: completion)
    }, event: { [weak self] in self?.emit($0) })

    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "proletarius/vowifi", binaryMessenger: registrar.messenger())
        let instance = ProletariusVowifiPlugin(channel: channel)
        registrar.addMethodCallDelegate(instance, channel: channel)
        registrar.publish(instance)
    }

    private init(channel: FlutterMethodChannel) {
        self.channel = channel
        super.init()
        observers.append(NotificationCenter.default.addObserver(forName: UIApplication.willTerminateNotification,
                                                                 object: nil, queue: .main) { [weak self] _ in
            self?.stop(phase: "stopped", completion: nil)
        })
        recovery.enteredBackground(allScenesBackground: UIApplication.shared.applicationState == .background)
        for name in [UIApplication.didEnterBackgroundNotification, UIScene.didEnterBackgroundNotification] {
            observers.append(NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) { [weak self] notification in
                guard let self = self else { return }
                // One scene entering background must not suspend another visible scene.
                let scenes = UIApplication.shared.connectedScenes
                let allBackground = notification.name == UIApplication.didEnterBackgroundNotification ||
                    (!scenes.isEmpty && scenes.allSatisfy { $0.activationState == .background || $0.activationState == .unattached })
                self.recovery.enteredBackground(allScenesBackground: allBackground)
                self.scheduleRecovery()
            })
        }
        for name in [UIApplication.willEnterForegroundNotification, UIApplication.didBecomeActiveNotification,
                     UIScene.willEnterForegroundNotification, UIScene.didActivateNotification] {
            observers.append(NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                guard let self = self else { return }
                // Inactive permission sheets and ordinary page navigation never arm this policy.
                self.recovery.enteredForeground()
                self.scheduleRecovery()
            })
        }
        pathMonitor.pathUpdateHandler = { [weak self] path in
            DispatchQueue.main.async { [weak self] in
                guard let self = self, !self.isDetached else { return }
                let changed = self.lastPath.map { $0 != path } ?? false
                self.lastPath = path
                self.recovery.pathUpdated(changed: changed)
                self.scheduleRecovery()
            }
        }
        pathMonitor.start(queue: pathQueue)
    }

    deinit {
        recoveryWork?.cancel()
        pathMonitor.cancel()
        observers.forEach(NotificationCenter.default.removeObserver)
    }

    public func detachFromEngine(for registrar: FlutterPluginRegistrar) {
        sessionLock.lock(); detached = true; sessionLock.unlock()
        pathMonitor.cancel()
        stop(phase: "stopped", completion: nil)
    }

    private func isCurrentRun(_ expected: VowifiRun) -> Bool {
        sessionLock.lock(); defer { sessionLock.unlock() }
        return !detached && run === expected && !expected.isCancelled
    }

    private func setRun(_ value: VowifiRun?) {
        sessionLock.lock(); run = value; sessionLock.unlock()
    }

    private var isDetached: Bool {
        sessionLock.lock(); defer { sessionLock.unlock() }
        return detached
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        dispatchPrecondition(condition: .onQueue(.main))
        switch call.method {
        case "reduceTransparency": result(UIAccessibility.isReduceTransparencyEnabled)
        case "status": refreshStatus(result: result)
        case "stop": stop(phase: "stopped", completion: result)
        case "start":
            guard let json = call.arguments as? String, let config = Self.object(json) else {
                result(Self.flutterError(bridgeError("start requires a JSON object string."))); return
            }
            start(json: json, config: config, result: result)
        case "command":
            guard let json = call.arguments as? String, var command = Self.object(json),
                  let action = command["action"] as? String else {
                result(Self.flutterError(bridgeError("command requires a JSON action object string."))); return
            }
            if action == "readCard", run == nil {
                readCard(command: command, result: result); return
            }
            if command["generation"] == nil, let generation = run?.generation { command["generation"] = generation }
            let completion: VowifiCalls.Completion = { response in
                switch response {
                case .success(let json): result(json)
                case .failure(let error): result(Self.flutterError(error))
                }
            }
            if action == "speaker" {
                audio.setSpeaker(command["enabled"] as? Bool ?? false) { error in
                    if let error = error { completion(.failure(error)) } else { completion(.success("{}")) }
                }
            } else if action == "mute" {
                calls.submit(command, completion: completion)
            } else if action == "dial" {
                guard let current = run, !current.cardOnly, !current.isCancelled else {
                    completion(.failure(bridgeError("Connect VoWiFi before calling."))); return
                }
                AVAudioSession.sharedInstance().requestRecordPermission { [weak self, weak current] granted in
                    DispatchQueue.main.async {
                        guard let self = self, let current = current, self.run === current else {
                            completion(.failure(bridgeError("VoWiFi session changed."))); return
                        }
                        guard granted else {
                            completion(.failure(bridgeError("Microphone permission is required to make a call."))); return
                        }
                        self.calls.submit(command, completion: completion)
                    }
                }
            } else {
                calls.submit(command, completion: completion)
            }
        default: result(FlutterMethodNotImplemented)
        }
    }

    private func makeRun(generation: Int64, cardOnly: Bool = false) -> VowifiRun {
        let current = VowifiRun(generation: generation, cardOnly: cardOnly)
        current.host.exchange = { [weak self, weak current] json, reply in
            guard let self = self, let current = current, self.isCurrentRun(current) else {
                DispatchQueue.main.async {
                    reply(Self.flutterError(bridgeError("SIM session changed.")))
                }
                return
            }
            guard let request = Self.object(json),
                  (request["generation"] as? NSNumber)?.int64Value == current.generation else {
                DispatchQueue.main.async {
                    reply(Self.flutterError(bridgeError("SIM reader generation changed.")))
                }
                return
            }
            DispatchQueue.main.async {
                guard self.isCurrentRun(current) else {
                    reply(Self.flutterError(bridgeError("SIM session changed."))); return
                }
                self.channel.invokeMethod("exchangeAPDUs", arguments: json, result: reply)
            }
        }
        current.host.store = { [weak self, weak current] json, reply in
            guard let self = self, let current = current, self.isCurrentRun(current),
                  let event = Self.object(json),
                  (event["generation"] as? NSNumber)?.int64Value == current.generation else {
                DispatchQueue.main.async {
                    reply(Self.flutterError(bridgeError("SMS session changed.")))
                }
                return
            }
            DispatchQueue.main.async {
                guard self.isCurrentRun(current) else {
                    reply(Self.flutterError(bridgeError("SMS session changed."))); return
                }
                self.channel.invokeMethod("storeSMS", arguments: json, result: reply)
            }
        }
        current.host.event = { [weak self, weak current] json in
            guard let self = self, let current = current, self.isCurrentRun(current),
                  let event = Self.object(json) else { return }
            if event["type"] as? String == "status" {
                self.recordStartupStatus(event)
                self.cachedStatus = json
                if ["failed", "stopped"].contains(event["phase"] as? String ?? "") {
                    self.calls.endAll()
                } else { self.calls.update(status: event) }
            }
            // A CallKit update may synchronously end the current session.
            // Recheck the run generation before forwarding a queued snapshot.
            guard self.isCurrentRun(current) else { return }
            self.channel.invokeMethod("event", arguments: json)
        }
        setRun(current)
        recovery.begin(runID: current.recoveryID, cardOnly: cardOnly)
        scheduleRecovery()
        return current
    }

    private func refreshStatus(result: @escaping FlutterResult) {
        guard let current = run, !current.isCancelled, let engine = current.snapshot() else {
            result(cachedStatus)
            return
        }
        current.operations.enter()
        control.async {
            defer { current.operations.leave() }
            let snapshot = engine.status()
            DispatchQueue.main.async {
                guard self.run === current, !current.isCancelled else {
                    result(self.cachedStatus)
                    return
                }
                var enriched = Self.object(snapshot) ?? [:]
                enriched["audio"] = self.audio.controlState()
                self.cachedStatus = jsonString(enriched)
                result(self.cachedStatus)
            }
        }
    }

    private func start(json: String, config: [String: Any], result: @escaping FlutterResult) {
        guard run == nil, retiringRun == nil, !stopping else {
            result(Self.flutterError(bridgeError("Stop the current VoWiFi session before connecting."))); return
        }
        guard UIApplication.shared.applicationState != .background else {
            result(Self.flutterError(bridgeError("Open the app to connect VoWiFi."))); return
        }
        let generation = (config["generation"] as? NSNumber)?.int64Value ?? 0
        let current = makeRun(generation: generation)
        emitStatus(phase: "sim", generation: generation)
        current.operations.enter()
        control.async {
            defer { current.operations.leave() }
            do {
                guard let engine = MobilecoreNewEngine(current.host) else { throw bridgeError("Cannot create the IMS engine.") }
                guard current.attach(engine) else { try? engine.stop(); throw bridgeError("Connection cancelled.") }
                try engine.start(json)
                guard !current.isCancelled else { throw bridgeError("Connection cancelled.") }
                let status = engine.status()
                DispatchQueue.main.async {
                    guard self.run === current, !current.isCancelled else {
                        result(Self.flutterError(bridgeError("Connection cancelled."))); return
                    }
                    self.audio.attach { [weak current = current] frame in
                        guard let current = current, !current.isCancelled else { return }
                        try engine.writePCM(frame)
                    }
                    self.beginPlayback(current, engine: engine)
                    self.recovery.started(runID: current.recoveryID)
                    self.scheduleRecovery()
                    result(status)
                }
            } catch {
                current.cancel()
                let failure = error
                try? current.snapshot()?.stop()
                DispatchQueue.main.async {
                    if self.run === current {
                        self.recovery.stop()
                        self.scheduleRecovery()
                        self.setRun(nil)
                        self.emitStatus(phase: "failed", generation: generation, error: failure.localizedDescription)
                    }
                    result(Self.flutterError(failure))
                }
            }
        }
    }

    private func readCard(command: [String: Any], result: @escaping FlutterResult) {
        guard !stopping, retiringRun == nil else {
            result(Self.flutterError(bridgeError("VoWiFi teardown must finish before reading the SIM."))); return
        }
        let generation = (command["generation"] as? NSNumber)?.int64Value ?? 0
        let current = makeRun(generation: generation, cardOnly: true)
        current.operations.enter()
        control.async {
            defer { current.operations.leave() }
            let response: Result<String, Error>
            do {
                guard let engine = MobilecoreNewEngine(current.host), current.attach(engine) else {
                    throw bridgeError("SIM session was cancelled.")
                }
                response = .success(try VowifiGoBridge.command(engine, request: jsonString(command)))
            } catch { response = .failure(error) }
            current.cancel()
            try? current.snapshot()?.stop()
            DispatchQueue.main.async {
                guard self.run === current else {
                    result(Self.flutterError(bridgeError("SIM session changed."))); return
                }
                self.setRun(nil)
                switch response {
                case .success(let json): result(json)
                case .failure(let error): result(Self.flutterError(error))
                }
            }
        }
    }

    private func execute(_ command: [String: Any], completion: @escaping VowifiCalls.Completion) {
        guard let current = run, !current.isCancelled else {
            completion(.failure(bridgeError("VoWiFi is not connected."))); return
        }
        guard pendingCommands < 8 else {
            completion(.failure(bridgeError("Too many pending VoWiFi actions."))); return
        }
        pendingCommands += 1
        var request = command
        if request["generation"] == nil { request["generation"] = current.generation }
        let json = jsonString(request)
        let action = request["action"] as? String ?? ""
        let worker = ["hangup", "reject"].contains(action) ? callEnding : control
        current.operations.enter()
        worker.async {
            defer { current.operations.leave() }
            let response: Result<String, Error>
            do {
                guard !current.isCancelled, let engine = current.snapshot() else {
                    throw bridgeError("VoWiFi session was cancelled.")
                }
                response = .success(try VowifiGoBridge.command(engine, request: json))
            } catch { response = .failure(error) }
            DispatchQueue.main.async {
                self.pendingCommands = max(0, self.pendingCommands - 1)
                guard self.run === current, !current.isCancelled else {
                    completion(.failure(bridgeError("VoWiFi session changed."))); return
                }
                completion(response)
            }
        }
    }

    private func beginPlayback(_ current: VowifiRun, engine: MobilecoreEngine) {
        // ReadPCM waits at most 500 ms. It never occupies the control queue,
        // and cancellation closes Go's audio socket to wake it immediately.
        DispatchQueue(label: "proletarius.vowifi.playback", qos: .userInteractive).async { [weak self] in
            while !current.isCancelled {
                autoreleasepool {
                    if let frame = engine.readPCM(), !current.isCancelled { self?.audio.receive(frame) }
                }
            }
        }
    }

    private func stop(phase: String, completion: FlutterResult?) {
        recovery.stop()
        scheduleRecovery()
        if let completion = completion { stopWaiters.append(completion) }
        // Background-task expiration and an explicit stop can race. All callers
        // wait for the same teardown before Dart releases the reader lease.
        guard !stopping else { return }
        let current = run ?? retiringRun
        setRun(nil)
        retiringRun = current
        stopping = current != nil
        current?.cancel()
        audio.stop()
        calls.endAll()
        emitStatus(phase: phase, generation: current?.generation ?? 0)
        guard let current = current else {
            let waiters = stopWaiters; stopWaiters.removeAll()
            waiters.forEach { $0(cachedStatus) }
            return
        }
        // A finite background task allows teardown of real sockets/APDUs only.
        var task: UIBackgroundTaskIdentifier = .invalid
        if UIApplication.shared.applicationState == .background {
            task = UIApplication.shared.beginBackgroundTask(withName: "VoWiFi teardown") {
                current.cancel()
                if task != .invalid { UIApplication.shared.endBackgroundTask(task); task = .invalid }
            }
        }
        cancellation.async {
            try? current.snapshot()?.stop()
            current.operations.notify(queue: self.cancellation) {
                // A queued Start can have attached just as the first Stop
                // observed an idle engine. After every control action drains,
                // confirm teardown again before releasing the reader lease.
                var failure: Error?
                do { try current.snapshot()?.stop() } catch { failure = error }
                DispatchQueue.main.async {
                    self.stopping = false
                    if failure == nil { self.retiringRun = nil }
                    if task != .invalid { UIApplication.shared.endBackgroundTask(task); task = .invalid }
                    if let failure = failure {
                        self.emit(["type": "native_error", "source": "stop", "generation": current.generation,
                                   "error": failure.localizedDescription])
                    }
                    let waiters = self.stopWaiters; self.stopWaiters.removeAll()
                    for waiter in waiters {
                        if let failure = failure { waiter(Self.flutterError(failure)) } else { waiter(self.cachedStatus) }
                    }
                }
            }
        }
    }

    private func emitStatus(phase: String, generation: Int64, error: String? = nil) {
        var status: [String: Any] = ["type": "status", "phase": phase, "generation": generation,
                                    "registered": false, "messaging_ready": false, "call_ready": false,
                                    "call": ["state": "idle", "media_ready": false]]
        if phase == "suspended" { status["reason"] = "Idle VoWiFi suspended in background. Open the app and reconnect." }
        if let error = error { status["error"] = error }
        cachedStatus = jsonString(status)
        recordStartupStatus(status)
        emit(status)
    }

    private func scheduleRecovery() {
        dispatchPrecondition(condition: .onQueue(.main))
        let ticket = recovery.ticket
        guard ticket != recoveryScheduledTicket else { return }
        recoveryWork?.cancel()
        recoveryWork = nil
        recoveryScheduledTicket = ticket
        guard let ticket = ticket, let current = run, !current.cardOnly,
              current.recoveryID == ticket.runID, isCurrentRun(current) else { return }
        let work = DispatchWorkItem { [weak self, weak current] in
            guard let self = self, let current = current,
                  self.recoveryScheduledTicket == ticket else { return }
            self.recoveryWork = nil
            self.recoveryScheduledTicket = nil
            guard self.isCurrentRun(current), self.recovery.take(ticket) else { return }
            self.checkConnection(current, reason: ticket.reason)
        }
        recoveryWork = work
        if ticket.reason == .foreground {
            // Submit before Flutter's next status refresh can observe a stale ready snapshot.
            work.perform()
        } else {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.75, execute: work)
        }
    }

    private func checkConnection(_ current: VowifiRun, reason: VowifiRecoveryPolicy.Reason) {
        // This requests the engine's non-blocking, coalesced liveness check.
        // The engine owns call-safe recovery; native code never stops a call here.
        let request = jsonString(["action": "check_connection", "generation": current.generation,
                                  "reason": reason.rawValue])
        recordRecovery(current, reason: reason, outcome: "requested")
        current.operations.enter()
        control.async {
            defer { current.operations.leave() }
            guard self.isCurrentRun(current), let engine = current.snapshot() else { return }
            let outcome: String
            do {
                _ = try VowifiGoBridge.command(engine, request: request)
                outcome = "accepted"
            } catch { outcome = "rejected" }
            DispatchQueue.main.async {
                guard self.isCurrentRun(current) else { return }
                // Preserve the engine's original status/error, including terminal auth failures.
                self.recordRecovery(current, reason: reason, outcome: outcome)
            }
        }
    }

    private func recordRecovery(_ current: VowifiRun, reason: VowifiRecoveryPolicy.Reason, outcome: String) {
        writeDiagnostic(["generation": current.generation, "recovery_reason": reason.rawValue,
                         "recovery_outcome": outcome])
    }

    // Allowlisted metadata only: no subscriber identity, APDUs, SIP or keys.
    // A bounded local file makes intermittent startup failures diagnosable.
    private func recordStartupStatus(_ status: [String: Any]) {
        var entry: [String: Any] = [:]
        for key in ["generation", "phase", "ike_stage", "attempt", "registered", "retrying", "terminal", "checking_connection"] {
            if let value = status[key] { entry[key] = value }
        }
        entry["has_error"] = status["error"] != nil
        let state = jsonString(entry)
        guard state != lastDiagnosticState else { return }
        lastDiagnosticState = state
        writeDiagnostic(entry)
    }

    private func writeDiagnostic(_ metadata: [String: Any]) {
        var entry = metadata
        entry["timestamp"] = ISO8601DateFormatter().string(from: Date())
        entry["build"] = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? ""
        guard let line = (jsonString(entry) + "\n").data(using: .utf8),
              let directory = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first else { return }
        diagnosticQueue.async {
            let url = directory.appendingPathComponent("vowifi-startup.jsonl")
            var data = (try? Data(contentsOf: url)) ?? Data()
            if data.count + line.count > 32768 { data = Data() }
            data.append(line)
            try? data.write(to: url, options: .atomic)
        }
    }

    private func emit(_ event: [String: Any]) {
        guard !isDetached else { return }
        var payload = event
        if payload["generation"] == nil { payload["generation"] = run?.generation ?? 0 }
        channel.invokeMethod("event", arguments: jsonString(payload))
    }

    private static func object(_ json: String) -> [String: Any]? {
        guard let data = json.data(using: .utf8) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }

    private static func flutterError(_ error: Error) -> FlutterError {
        FlutterError(code: "VOWIFI_ERROR", message: error.localizedDescription, details: nil)
    }
}
