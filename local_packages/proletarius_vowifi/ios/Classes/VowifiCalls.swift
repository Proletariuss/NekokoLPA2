import AVFoundation
import CallKit
import Foundation

/// All CallKit bookkeeping runs on the main queue. Signaling is supplied by
/// the plugin and always executes on a worker queue.
final class VowifiCalls: NSObject, CXProviderDelegate {
    typealias Completion = (Result<String, Error>) -> Void
    typealias Execute = ([String: Any], @escaping Completion) -> Void
    private let provider: CXProvider
    private let controller = CXCallController()
    private let audio: VowifiAudio
    private let execute: Execute
    private let event: ([String: Any]) -> Void
    private var callUUID: UUID?
    private var callID: String?
    private var direction = ""
    private var state = "idle"
    private var generation: Int64 = 0
    private var awaitingEngine = false
    private var finishedCallIDs: [String] = []
    private var pending: [UUID: ([String: Any], Completion)] = [:]
    private var lastMediaDiagnostic = Date.distantPast

    var hasCall: Bool { callUUID != nil }

    init(audio: VowifiAudio, execute: @escaping Execute,
         event: @escaping ([String: Any]) -> Void) {
        self.audio = audio
        self.execute = execute
        self.event = event
        // The system resolves the current app display name from the bundle.
        let configuration = CXProviderConfiguration()
        configuration.supportsVideo = false
        configuration.maximumCallGroups = 1
        configuration.maximumCallsPerCallGroup = 1
        configuration.supportedHandleTypes = [.phoneNumber, .generic]
        configuration.includesCallsInRecents = false
        provider = CXProvider(configuration: configuration)
        super.init()
        provider.setDelegate(self, queue: .main)
    }

    deinit { provider.invalidate() }

    func submit(_ command: [String: Any], completion: @escaping Completion) {
        dispatchPrecondition(condition: .onQueue(.main))
        let name = command["action"] as? String ?? ""
        if name == "dial" {
            guard callUUID == nil else { completion(.failure(Self.error("A call is already in progress."))); return }
            guard let peer = command["peer"] as? String, !peer.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                completion(.failure(Self.error("A destination is required."))); return
            }
            let uuid = UUID()
            // A mute selection belongs to this call, not the long-lived IMS
            // registration. Reset before the new call can acquire audio.
            audio.setMuted(false)
            callUUID = uuid
            direction = "outgoing"
            state = "outgoing"
            generation = (command["generation"] as? NSNumber)?.int64Value ?? 0
            awaitingEngine = true
            let action = CXStartCallAction(call: uuid, handle: CXHandle(type: .phoneNumber, value: peer))
            action.isVideo = false
            request(action, command: command, completion: completion)
        } else if name == "answer" {
            guard let uuid = callUUID, direction == "incoming", state == "incoming" else {
                completion(.failure(Self.error("There is no incoming call to answer."))); return
            }
            request(CXAnswerCallAction(call: uuid), command: command, completion: completion)
        } else if name == "hangup" || name == "reject" {
            guard let uuid = callUUID else {
                // A failed CallKit report can leave signaling briefly alive.
                execute(command, completion); return
            }
            request(CXEndCallAction(call: uuid), command: command, completion: completion)
        } else if name == "mute" {
            guard let uuid = callUUID else {
                completion(.failure(Self.error("There is no active call to mute."))); return
            }
            if let requestedGeneration = command["generation"] as? NSNumber,
               requestedGeneration.int64Value != generation {
                completion(.failure(Self.error("The call session changed."))); return
            }
            // Use the same transaction as the system call screen so CallKit's
            // mute indicator and the actual capture state cannot diverge.
            let action = CXSetMutedCallAction(call: uuid, muted: command["enabled"] as? Bool ?? false)
            request(action, command: command, completion: completion)
        } else {
            execute(command, completion)
        }
    }

    private func request(_ action: CXCallAction, command: [String: Any], completion: @escaping Completion) {
        pending[action.uuid] = (command, completion)
        controller.request(CXTransaction(action: action)) { [weak self] error in
            DispatchQueue.main.async {
                guard let self = self, let error = error else { return }
                self.pending.removeValue(forKey: action.uuid)?.1(.failure(Self.describeRequestError(error)))
                if action is CXStartCallAction, self.callUUID == action.callUUID {
                    self.finish(reason: .failed)
                }
            }
        }
    }

    func update(status: [String: Any]) {
        dispatchPrecondition(condition: .onQueue(.main))
        guard let call = status["call"] as? [String: Any] else { return }
        let nextState = call["state"] as? String ?? "idle"
        let nextID = call["call_id"] as? String ?? ""
        let nextDirection = call["direction"] as? String ?? ""
        if !nextID.isEmpty, finishedCallIDs.contains(nextID) { return }
        let terminal = ["idle", "unavailable", "ended", "failed", "rejected", "busy"].contains(nextState)
        if let currentID = callID, !currentID.isEmpty, !nextID.isEmpty, currentID != nextID { return }
        if terminal {
            if !awaitingEngine, callUUID != nil {
                finish(reason: nextState == "failed" ? .failed : (state == "incoming" ? .unanswered : .remoteEnded))
            }
            return
        }
        if nextState == "incoming", callUUID == nil {
            generation = (status["generation"] as? NSNumber)?.int64Value ?? 0
            let uuid = UUID()
            audio.setMuted(false)
            callUUID = uuid
            callID = nextID
            direction = "incoming"
            state = nextState
            let update = CXCallUpdate()
            update.remoteHandle = CXHandle(type: .phoneNumber, value: call["peer"] as? String ?? "Unknown")
            update.hasVideo = false
            update.supportsHolding = false
            update.supportsGrouping = false
            update.supportsUngrouping = false
            update.supportsDTMF = true
            provider.reportNewIncomingCall(with: uuid, update: update) { [weak self] error in
                DispatchQueue.main.async {
                    guard let self = self, let error = error, self.callUUID == uuid else { return }
                    self.event(["type": "native_error", "source": "callkit", "error": error.localizedDescription])
                    self.execute(["action": "reject", "generation": self.generation]) { _ in }
                    self.finish(reason: .failed)
                }
            }
        }
        guard let uuid = callUUID else { return }
        // A stale snapshot from a completed dialog cannot end a newer one.
        if let currentID = callID, !currentID.isEmpty, !nextID.isEmpty, currentID != nextID { return }
        if !nextID.isEmpty { callID = nextID; awaitingEngine = false }
        if !nextDirection.isEmpty { direction = nextDirection }
        let previousState = state
        state = nextState
        if direction == "outgoing", nextState == "active", previousState != "active" {
            provider.reportOutgoingCall(with: uuid, connectedAt: Date())
        }
        let mediaReady = call["media_ready"] as? Bool ?? false
        if mediaReady, Date().timeIntervalSince(lastMediaDiagnostic) >= 5 {
            lastMediaDiagnostic = Date()
            // No number, SIM identity, endpoint or audio payload is logged.
            NSLog("[VoWiFi media] state=%@ codec=%@ tx=%@ rx=%@ decodeErrors=%@ transportErrors=%@",
                  nextState, call["codec"] as? String ?? "unknown",
                  String(describing: call["rtp_transmitted"] ?? 0),
                  String(describing: call["rtp_received"] ?? 0),
                  String(describing: call["audio_decode_errors"] ?? 0),
                  String(describing: call["audio_transport_errors"] ?? 0))
        }
        audio.setMediaReady(mediaReady && ["early", "connecting", "active"].contains(nextState))
    }

    func endAll() { finish(reason: .remoteEnded) }

    private func finish(reason: CXCallEndedReason) {
        if let uuid = callUUID { provider.reportCall(with: uuid, endedAt: Date(), reason: reason) }
        if let callID = callID, !callID.isEmpty {
            finishedCallIDs.append(callID)
            if finishedCallIDs.count > 16 { finishedCallIDs.removeFirst() }
        }
        callUUID = nil; callID = nil; direction = ""; state = "idle"
        awaitingEngine = false
        lastMediaDiagnostic = .distantPast
        audio.setMediaReady(false)
        let callbacks = pending.values.map { $0.1 }
        pending.removeAll()
        callbacks.forEach { $0(.failure(Self.error("The call ended before the action completed."))) }
    }

    private func perform(_ action: CXCallAction, fallback: String) {
        guard action.callUUID == callUUID else { Self.complete(action, succeeded: false); return }
        guard Self.isPending(action) else { return }
        let queued = pending.removeValue(forKey: action.uuid)
        let command = queued?.0 ?? ["action": fallback, "generation": generation]
        let started = action is CXStartCallAction
        if started {
            // CallKit's action deadline must not depend on SIP transmission
            // or the remote party answering. A signaling failure ends the
            // reported call asynchronously below.
            action.fulfill()
            provider.reportOutgoingCall(with: action.callUUID, startedConnectingAt: Date())
        }
        execute(command) { [weak self] result in
            guard let self = self else { if !started { Self.complete(action, succeeded: false) }; return }
            guard self.callUUID == action.callUUID else {
                if !started {
                    Self.complete(action, succeeded: action is CXEndCallAction)
                }
                queued?.1(result)
                return
            }
            switch result {
            case .success:
                if !started { Self.complete(action, succeeded: true) }
                if action is CXEndCallAction {
                    self.finish(reason: .remoteEnded)
                }
            case .failure(let error):
                if !started { Self.complete(action, succeeded: false) }
                // System-screen actions have no Dart command completion. Send
                // failures to the app as well, instead of silently returning
                // the incoming screen to its previous state.
                if queued == nil {
                    self.event(["type": "native_error", "source": "callkit", "error": error.localizedDescription])
                }
                if action is CXStartCallAction { self.finish(reason: .failed) }
            }
            queued?.1(result)
        }
    }

    func providerDidReset(_ provider: CXProvider) {
        if callUUID != nil { execute(["action": "hangup", "generation": generation]) { _ in } }
        finish(reason: .failed)
        audio.deactivate()
    }

    func provider(_ provider: CXProvider, perform action: CXStartCallAction) {
        do { try VowifiAudio.configureSession() } catch {
            pending.removeValue(forKey: action.uuid)?.1(.failure(error))
            action.fail(); finish(reason: .failed); return
        }
        perform(action, fallback: "dial")
    }

    func provider(_ provider: CXProvider, perform action: CXAnswerCallAction) {
        guard action.callUUID == callUUID, direction == "incoming", state == "incoming" else {
            Self.complete(action, succeeded: false); return
        }
        let answeringGeneration = generation
        AVAudioSession.sharedInstance().requestRecordPermission { [weak self] granted in
            DispatchQueue.main.async {
                guard let self = self else { Self.complete(action, succeeded: false); return }
                // Permission sheets can outlive the call. A caller may cancel
                // while the sheet is visible, then another call can arrive.
                // Never reject or answer that newer dialog on this callback.
                guard self.callUUID == action.callUUID, self.generation == answeringGeneration else {
                    Self.complete(action, succeeded: false); return
                }
                guard Self.isPending(action) else { return }
                guard granted else {
                    let error = Self.error("Microphone permission is required to answer.")
                    self.pending.removeValue(forKey: action.uuid)?.1(.failure(error))
                    self.event(["type": "native_error", "source": "callkit", "error": error.localizedDescription])
                    Self.complete(action, succeeded: false)
                    self.execute(["action": "reject", "generation": self.generation]) { _ in }
                    self.finish(reason: .failed)
                    return
                }
                do { try VowifiAudio.configureSession() } catch {
                    self.pending.removeValue(forKey: action.uuid)?.1(.failure(error))
                    self.event(["type": "native_error", "source": "callkit", "error": error.localizedDescription])
                    Self.complete(action, succeeded: false); return
                }
                self.perform(action, fallback: "answer")
            }
        }
    }

    func provider(_ provider: CXProvider, perform action: CXEndCallAction) {
        perform(action, fallback: direction == "incoming" && state == "incoming" ? "reject" : "hangup")
    }

    func provider(_ provider: CXProvider, perform action: CXSetMutedCallAction) {
        let completion = pending.removeValue(forKey: action.uuid)?.1
        guard action.callUUID == callUUID else {
            Self.complete(action, succeeded: false)
            completion?(.failure(Self.error("The call ended before the mute action completed.")))
            return
        }
        guard Self.isPending(action) else {
            completion?(.failure(Self.error("The mute action timed out.")))
            return
        }
        audio.setMuted(action.isMuted)
        event(["type": "audio", "muted": action.isMuted])
        Self.complete(action, succeeded: true)
        completion?(.success("{}"))
    }

    func provider(_ provider: CXProvider, perform action: CXSetHeldCallAction) { action.fail() }

    func provider(_ provider: CXProvider, perform action: CXPlayDTMFCallAction) {
        guard action.callUUID == callUUID else { Self.complete(action, succeeded: false); return }
        let sendingGeneration = generation
        func send(_ remaining: ArraySlice<Character>) {
            guard action.callUUID == callUUID, generation == sendingGeneration else {
                Self.complete(action, succeeded: false); return
            }
            guard Self.isPending(action) else { return }
            guard let first = remaining.first else { Self.complete(action, succeeded: true); return }
            execute(["action": "dtmf", "digit": String(first), "generation": sendingGeneration]) { result in
                switch result {
                case .success: send(remaining.dropFirst())
                case .failure: Self.complete(action, succeeded: false)
                }
            }
        }
        send(Array(action.digits)[...])
    }

    func provider(_ provider: CXProvider, timedOutPerforming action: CXAction) {
        pending.removeValue(forKey: action.uuid)?.1(.failure(Self.error("The system call action timed out.")))
        // CallKit may deliver an old timeout after another call has started.
        guard let callAction = action as? CXCallAction, callAction.callUUID == callUUID else { return }
        event(["type": "native_error", "source": "callkit", "error": "The system call action timed out."])
        // A failed control transaction must not tear down an otherwise healthy
        // call. The provider has not applied a timed-out mute action.
        if action is CXSetMutedCallAction { return }
        execute(["action": "hangup", "generation": generation]) { _ in }
        finish(reason: .failed)
    }

    func provider(_ provider: CXProvider, didActivate audioSession: AVAudioSession) { audio.activate() }
    func provider(_ provider: CXProvider, didDeactivate audioSession: AVAudioSession) { audio.deactivate() }

    private static func error(_ message: String) -> NSError {
        NSError(domain: "VowifiCallKit", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }

    private static func isPending(_ action: CXAction) -> Bool {
        !action.isComplete && action.timeoutDate > Date()
    }

    private static func complete(_ action: CXAction, succeeded: Bool) {
        // Apple explicitly forbids fulfilling/failing an already timed-out
        // action. Network and microphone-permission callbacks are asynchronous.
        guard isPending(action) else { return }
        if succeeded { action.fulfill() } else { action.fail() }
    }

    private static func describeRequestError(_ error: Error) -> Error {
        let native = error as NSError
        // Apple maps CXErrorCodeRequestTransactionErrorUnentitled to code 1.
        // It is commonly caused by omitting UIBackgroundModes = voip.
        guard native.domain.lowercased().contains("requesttransaction"), native.code == 1 else {
            return error
        }
        return NSError(
            domain: native.domain,
            code: native.code,
            userInfo: [
                NSLocalizedDescriptionKey: "CallKit rejected the transaction because the app needs the VoIP background mode.",
                NSUnderlyingErrorKey: native,
            ]
        )
    }
}
