import Foundation

// Compile with Classes/VowifiRecoveryPolicy.swift; this test needs no iOS SDK.
@main
struct RecoveryPolicyTests {
    static func main() {
        var checks = 0
        func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
            checks += 1
            precondition(condition(), message)
        }

        let first = UUID(), replacement = UUID()
        var policy = VowifiRecoveryPolicy()
        policy.begin(runID: first, cardOnly: false)
        policy.started(runID: first)
        policy.pathUpdated(changed: true)
        expect(policy.ticket == nil, "First network snapshot is only a baseline")
        policy.enteredForeground()
        policy.enteredForeground()
        expect(policy.ticket == nil, "Inactive/active permission notifications do not check")
        policy.enteredBackground(allScenesBackground: false)
        policy.enteredForeground()
        expect(policy.ticket == nil, "One background scene must not arm a visible app")

        policy.enteredBackground(allScenesBackground: true)
        policy.enteredBackground(allScenesBackground: true)
        expect(policy.ticket == nil, "No command while background")
        policy.enteredForeground()
        let foreground = policy.ticket!
        expect(foreground.reason == .foreground, "Real foreground checks once")
        policy.enteredForeground()
        policy.enteredForeground()
        expect(policy.ticket == foreground, "Scene and application notifications are deduplicated")
        expect(policy.take(foreground), "Current foreground ticket is consumed")
        expect(!policy.take(foreground), "A ticket cannot run twice")
        policy.enteredForeground()
        expect(policy.ticket == nil, "Repeated active notification does not loop")

        policy.pathUpdated(changed: false)
        expect(policy.ticket == nil, "Equivalent path notifications do not check")
        policy.pathUpdated(changed: true)
        let network = policy.ticket!
        expect(network.reason == .networkChanged, "Changed path checks")
        policy.pathUpdated(changed: false)
        expect(policy.ticket == network, "Duplicate path does not restart debounce")
        policy.pathUpdated(changed: true)
        let latestNetwork = policy.ticket!
        expect(latestNetwork != network, "A newer change resets debounce")
        expect(!policy.take(network), "An older debounce callback is stale")
        policy.enteredBackground(allScenesBackground: true)
        expect(!policy.take(latestNetwork), "Background invalidates queued work")
        policy.pathUpdated(changed: true)
        expect(policy.ticket == nil, "Background path changes wait")
        policy.enteredForeground()
        expect(policy.ticket?.reason == .foreground, "Foreground supersedes pending network changes")
        policy.pathUpdated(changed: true)
        expect(policy.ticket?.reason == .foreground, "Debounced network event preserves foreground reason")
        let beforeStop = policy.ticket!
        policy.stop()
        expect(policy.ticket == nil && !policy.take(beforeStop), "Stop cancels every pending callback")
        policy.pathUpdated(changed: true)
        policy.enteredBackground(allScenesBackground: true)
        policy.enteredForeground()
        expect(policy.ticket == nil, "Idle events never create a connection")

        policy.begin(runID: replacement, cardOnly: false)
        policy.enteredBackground(allScenesBackground: true)
        policy.enteredForeground()
        policy.pathUpdated(changed: true)
        expect(policy.ticket == nil, "Start must finish before check is eligible")
        policy.started(runID: first)
        expect(policy.ticket == nil, "Old start completion cannot enable a new run")
        policy.started(runID: replacement)
        let ready = policy.ticket!
        expect(ready.runID == replacement && ready.reason == .foreground, "Startup retains one merged request")
        expect(!policy.take(beforeStop), "Prior run cannot consume a replacement's request")
        expect(policy.take(ready), "Completed start permits the pending check")
        expect(policy.ticket == nil, "No recurring timer or automatic follow-up")

        policy.begin(runID: first, cardOnly: true)
        policy.started(runID: first)
        policy.pathUpdated(changed: true)
        policy.enteredBackground(allScenesBackground: true)
        policy.enteredForeground()
        expect(policy.ticket == nil, "Card-only operations never check connection")
        policy.begin(runID: first, cardOnly: false)
        policy.started(runID: first)
        expect(policy.ticket == nil, "Fresh start does not inherit earlier lifecycle work")
        policy.pathUpdated(changed: true)
        let reusedID = policy.ticket!
        policy.stop()
        policy.begin(runID: first, cardOnly: false)
        policy.started(runID: first)
        policy.pathUpdated(changed: true)
        expect(!policy.take(reusedID), "Revision also rejects stale work if a run ID is reused")

        var initiallyBackground = VowifiRecoveryPolicy()
        initiallyBackground.enteredBackground(allScenesBackground: true)
        initiallyBackground.enteredForeground()
        initiallyBackground.begin(runID: first, cardOnly: false)
        initiallyBackground.started(runID: first)
        expect(initiallyBackground.ticket == nil, "Initial app activation cannot reconnect a future run")
        print("PASS: \(checks) VoWiFi recovery policy checks")
    }
}
