import Foundation

/// Main-queue owned policy, deliberately independent of UIKit and Network.
/// A native UUID distinguishes runs even if a caller reuses a generation.
struct VowifiRecoveryPolicy {
    enum Reason: String { case foreground, networkChanged = "network_changed" }
    struct Ticket: Equatable {
        let runID: UUID
        let revision: UInt64
        let reason: Reason
    }

    private var runID: UUID?
    private var ready = false
    private var background = false
    private var hasPathSnapshot = false
    private var revision: UInt64 = 0
    private var pending: Reason?

    var ticket: Ticket? {
        guard let runID = runID, ready, !background, let pending = pending else { return nil }
        return Ticket(runID: runID, revision: revision, reason: pending)
    }

    mutating func begin(runID: UUID, cardOnly: Bool) {
        stop()
        self.runID = cardOnly ? nil : runID
    }

    mutating func stop() {
        runID = nil
        ready = false
        pending = nil
        revision &+= 1
    }

    mutating func started(runID: UUID) {
        guard self.runID == runID else { return }
        ready = true
    }

    mutating func enteredBackground(allScenesBackground: Bool) {
        guard allScenesBackground, !background else { return }
        background = true
        revision &+= 1
    }

    mutating func enteredForeground() {
        guard background else { return }
        background = false
        request(.foreground)
    }

    /// The monitor's first delivery is a baseline, never a reconnect trigger.
    mutating func pathUpdated(changed: Bool) {
        defer { hasPathSnapshot = true }
        guard hasPathSnapshot, changed else { return }
        request(.networkChanged)
    }

    mutating func take(_ expected: Ticket) -> Bool {
        guard ticket == expected else { return false }
        pending = nil
        return true
    }

    private mutating func request(_ reason: Reason) {
        guard runID != nil else { return }
        if pending != .foreground { pending = reason }
        revision &+= 1
    }
}
