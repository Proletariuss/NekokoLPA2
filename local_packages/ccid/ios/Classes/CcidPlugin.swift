import Flutter
import UIKit
import CryptoTokenKit
import Foundation

extension String {
    var hexadecimal: Data? {
        guard !isEmpty, count.isMultiple(of: 2), count <= 131080,
            allSatisfy({ $0.isHexDigit && $0.isASCII })
        else { return nil }
        var data = Data(capacity: count / 2)

        var cursor = startIndex
        while cursor < endIndex {
            let next = index(cursor, offsetBy: 2)
            guard let byte = UInt8(self[cursor..<next], radix: 16) else { return nil }
            data.append(byte)
            cursor = next
        }

        guard data.count > 0 else { return nil }

        return data
    }
}

extension Data {
    var hexadecimal: String {
        return map { String(format: "%02x", $0) }.joined()
    }
}

public class CcidPlugin: NSObject, FlutterPlugin {
    var cards: [String: TKSmartCard] = [:]
    // Retain SELECT/AUTHENTICATE state for the duration of a VoWiFi lease.
    private var retainedSessions: Set<String> = []
    private var busyReaders: Set<String> = []

    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "ccid", binaryMessenger: registrar.messenger())
        let instance = CcidPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "listReaders":
            let manager = TKSmartCardSlotManager.default
            result(manager?.slotNames ?? [])
            
        case "listReaderATRs":
            guard let manager = TKSmartCardSlotManager.default else {
                result([:]) // Return an empty map if the manager is not available
                return
            }

            var slotATRMap = [String: String]()

            // Access all slot names
            for slotName in manager.slotNames {
                if let slot = manager.slotNamed(slotName),
                   slot.makeSmartCard() != nil {

                    // Get the ATR in hexadecimal
                    if let atrData = slot.atr?.bytes.hexadecimal {
                        slotATRMap[slotName] = atrData
                    } else {
                        slotATRMap[slotName] = ""
                    }
                } else {
                    slotATRMap[slotName] = "[NO_CARD]"
                }
            }
            result(slotATRMap)

        case "connect":
            guard let reader = call.arguments as? String else {
                result(FlutterError(code: "INVALID_ARGUMENT", message: "无效的读卡器名称", details: nil))
                return
            }
            guard cards[reader] == nil, !busyReaders.contains(reader) else {
                result(FlutterError(code: "ALREADY_CONNECTED", message: "请先断开旧读卡会话", details: nil))
                return
            }
            let manager = TKSmartCardSlotManager.default
            if let slot = manager?.slotNamed(reader) {
                if let card = slot.makeSmartCard() {
                    cards[reader] = card
                    result(slot.atr?.bytes.hexadecimal)
                } else {
                    result(FlutterError(code: "NO_CARD", message: "Failed to find a card", details: nil))
                }
            } else {
                result(FlutterError(code: "INVALID_READER", message: "Invalid reader name", details: nil))
            }

        case "beginSession":
            guard let reader = call.arguments as? String,
                let card = cards[reader], card.isValid
            else {
                result(FlutterError(code: "DISCONNECTED", message: "USB 读卡器未连接", details: nil))
                return
            }
            guard !busyReaders.contains(reader), !retainedSessions.contains(reader) else {
                result(FlutterError(code: "READER_BUSY", message: "读卡器正忙", details: nil))
                return
            }
            busyReaders.insert(reader)
            card.beginSession { success, error in
                DispatchQueue.main.async {
                    self.busyReaders.remove(reader)
                    guard success else {
                        result(self.mapTKError(error, defaultCode: "BEGIN_SESSION_ERROR"))
                        return
                    }
                    guard self.cards[reader] === card else {
                        card.endSession()
                        result(FlutterError(code: "DISCONNECTED", message: "USB 读卡器已断开", details: nil))
                        return
                    }
                    self.retainedSessions.insert(reader)
                    result(nil)
                }
            }

        case "endSession":
            guard let reader = call.arguments as? String else {
                result(FlutterError(code: "INVALID_ARGUMENT", message: "无效的读卡器名称", details: nil))
                return
            }
            if retainedSessions.remove(reader) != nil, !busyReaders.contains(reader) {
                cards[reader]?.endSession()
            }
            result(nil)

        case "transceive":
            guard let args = call.arguments as? [String: Any],
                let reader = args["reader"] as? String,
                let capdu = args["capdu"] as? String,
                let capduData = capdu.hexadecimal, capduData.count >= 4
            else {
                result(FlutterError(code: "INVALID_ARGUMENT", message: "无效的 APDU", details: nil))
                return
            }
            guard !busyReaders.contains(reader) else {
                result(FlutterError(code: "READER_BUSY", message: "读卡器正忙", details: nil))
                return
            }

            if cards[reader] == nil {
                result(FlutterError(code: "DISCONNECTED", message: "USB 读卡器未连接", details: nil))
            } else {
                let card = cards[reader]!
                if card.isValid {
                    busyReaders.insert(reader)
                    if retainedSessions.contains(reader) {
                        transmitRetained(card, reader: reader, data: capduData, result: result)
                        return
                    }
                    card.beginSession { (success, error) in
                        DispatchQueue.main.async {
                            if !success {
                                self.busyReaders.remove(reader)
                                result(self.mapTKError(error, defaultCode: "BEGIN_SESSION_ERROR"))
                                return
                            }
                            guard self.cards[reader] === card else {
                                self.busyReaders.remove(reader)
                                card.endSession()
                                result(FlutterError(code: "DISCONNECTED", message: "USB 读卡器已断开", details: nil))
                                return
                            }
                            card.transmit(capduData) { (rapdu, error) in
                                DispatchQueue.main.async {
                                    self.busyReaders.remove(reader)
                                    card.endSession()
                                    guard self.cards[reader] === card else {
                                        result(FlutterError(code: "DISCONNECTED", message: "USB 读卡器已断开", details: nil))
                                        return
                                    }
                                    if let rapdu = rapdu {
                                        result(rapdu.hexadecimal)
                                    } else {
                                        result(self.mapTKError(error, defaultCode: "TRANSMIT_ERROR"))
                                    }
                                }
                            }
                        }
                    }
                } else {
                    if retainedSessions.remove(reader) != nil { card.endSession() }
                    cards.removeValue(forKey: reader)
                    result(FlutterError(code: "DISCONNECTED", message: "USB 卡片已失效，请重新连接", details: nil))
                }
            }

        case "disconnect":
            guard let reader = call.arguments as? String else {
                result(FlutterError(code: "INVALID_ARGUMENT", message: "无效的读卡器名称", details: nil))
                return
            }
            if retainedSessions.remove(reader) != nil, !busyReaders.contains(reader) {
                cards[reader]?.endSession()
            }
            cards.removeValue(forKey: reader)
            result(nil)

        default:
            result(FlutterMethodNotImplemented)
        }
    }

    private func transmitRetained(
        _ card: TKSmartCard, reader: String, data: Data, result: @escaping FlutterResult
    ) {
        card.transmit(data) { response, error in
            DispatchQueue.main.async {
                self.busyReaders.remove(reader)
                if !self.retainedSessions.contains(reader) { card.endSession() }
                guard self.cards[reader] === card else {
                    result(FlutterError(code: "DISCONNECTED", message: "USB 读卡器已断开", details: nil))
                    return
                }
                if let response {
                    result(response.hexadecimal)
                } else {
                    result(self.mapTKError(error, defaultCode: "TRANSMIT_ERROR"))
                }
            }
        }
    }

    private func mapTKError(_ optionalError: Error?, defaultCode: String) -> FlutterError {
        guard let error = optionalError else {
            return FlutterError(code: defaultCode, message: "读卡器通信中断", details: nil)
        }
        let nsError = error as NSError
        if nsError.domain == TKErrorDomain {
            switch nsError.code {
            case TKError.Code.authenticationNeeded.rawValue:
                return FlutterError(code: "AuthenticationNeeded", message: error.localizedDescription, details: nil)
            case TKError.Code.badParameter.rawValue:
                return FlutterError(code: "BadParameter", message: error.localizedDescription, details: nil)
            case TKError.Code.tokenNotFound.rawValue:
                return FlutterError(code: "TokenNotFound", message: error.localizedDescription, details: nil)
            case TKError.Code.objectNotFound.rawValue:
                return FlutterError(code: "ObjectNotFound", message: error.localizedDescription, details: nil)
            case TKError.Code.authenticationFailed.rawValue:
                return FlutterError(code: "AuthenticationFailed", message: error.localizedDescription, details: nil)
            case TKError.Code.canceledByUser.rawValue:
                return FlutterError(code: "CanceledByUser", message: error.localizedDescription, details: nil)
            case TKError.Code.corruptedData.rawValue:
                return FlutterError(code: "CorruptedData", message: error.localizedDescription, details: nil)
            case TKError.Code.communicationError.rawValue:
                return FlutterError(code: "CommunicationError", message: error.localizedDescription, details: nil)
            case TKError.Code.notImplemented.rawValue:
                return FlutterError(code: "NotImplemented", message: error.localizedDescription, details: nil)
            default:
                break
            }
        }
        return FlutterError(code: defaultCode, message: error.localizedDescription, details: "\(nsError.domain):\(nsError.code)")
    }
}
