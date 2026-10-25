import 'package:flutter/widgets.dart';
import '../l10n/app_localizations.dart';
import '../l10n/app_localizations_en.dart';

// English is the upstream fallback when a host has no localization delegate.
AppLocalizations voWifiL10n(BuildContext context) =>
    AppLocalizations.of(context) ?? AppLocalizationsEn();

String localizedVoWifiError(
  BuildContext context,
  String message,
) => switch (message) {
  "IMEI must contain 15 digits" => voWifiL10n(
    context,
  ).voWifiIMEIMustContain15Digits,
  "IMEI must have 15 digits and a valid check digit" => voWifiL10n(
    context,
  ).voWifiIMEIMustHave15DigitsAndAValidCheck,
  "Could not save Wi-Fi calling settings" => voWifiL10n(
    context,
  ).voWifiCouldNotSaveWiFiCallingSettings,
  "The native Wi-Fi calling engine is unavailable in this build" => voWifiL10n(
    context,
  ).voWifiTheNativeWiFiCallingEngineIsUnavailableIn,
  "CallKit rejected the transaction because the app needs the VoIP background mode." =>
    voWifiL10n(
      context,
    ).voWifiCallKitRejectedTheTransactionBecauseTheAppNeedsThe,
  "A Wi-Fi calling session is already active" => voWifiL10n(
    context,
  ).voWifiAWiFiCallingSessionIsAlreadyActive,
  "This reader does not support Wi-Fi calling" => voWifiL10n(
    context,
  ).voWifiThisReaderDoesNotSupportWiFiCalling,
  "Connect this reader in Manage before starting Wi-Fi calling" => voWifiL10n(
    context,
  ).voWifiConnectThisReaderInManageBeforeStartingWiFi,
  "The SIM reader disconnected" => voWifiL10n(
    context,
  ).voWifiTheSIMReaderDisconnected,
  "The active SIM did not provide an IMSI" => voWifiL10n(
    context,
  ).voWifiTheActiveSIMDidNotProvideAnIMSI,
  "Wi-Fi calling is not ready" => voWifiL10n(
    context,
  ).voWifiWiFiCallingIsNotReady,
  "Checking connection…" => voWifiL10n(context).voWifiCheckingConnection,
  "IMS messaging is not registered" => voWifiL10n(
    context,
  ).voWifiIMSMessagingIsNotRegistered,
  "SIM session changed" => voWifiL10n(context).voWifiSIMSessionChanged,
  "SIM session has ended" => voWifiL10n(context).voWifiSIMSessionHasEnded,
  "SIM session was cancelled." => voWifiL10n(
    context,
  ).voWifiSIMSessionWasCancelled,
  "Incoming SMS could not be saved on this device" => voWifiL10n(
    context,
  ).voWifiIncomingSMSCouldNotBeSavedOnThisDevice,
  "Microphone permission is required to make a call." => voWifiL10n(
    context,
  ).voWifiMicrophonePermissionIsRequiredToMakeACall,
  "Open the app to connect VoWiFi." => voWifiL10n(
    context,
  ).voWifiOpenTheAppToConnectVoWiFi,
  "Stop the current VoWiFi session before connecting." => voWifiL10n(
    context,
  ).voWifiStopTheCurrentVoWiFiSessionBeforeConnecting,
  "Connection cancelled." => voWifiL10n(context).voWifiConnectionCancelled,
  "The SIM reader did not answer within 30 seconds." => voWifiL10n(
    context,
  ).voWifiTheSIMReaderDidNotAnswerWithin30Seconds,
  'Could not confirm the current connection state' => voWifiL10n(
    context,
  ).voWifiCouldNotConfirmConnectionState,
  "Call history could not be saved on this device" => voWifiL10n(
    context,
  ).voWifiCallHistoryCouldNotBeSavedOnThisDevice,
  "Cannot correct SIM command length" => voWifiL10n(
    context,
  ).voWifiCannotCorrectSIMCommandLength,
  "Incomplete SIM response" => voWifiL10n(context).voWifiIncompleteSIMResponse,
  "Invalid SIM command batch" => voWifiL10n(
    context,
  ).voWifiInvalidSIMCommandBatch,
  "Invalid SIM command batch size" => voWifiL10n(
    context,
  ).voWifiInvalidSIMCommandBatchSize,
  "Invalid SIM command encoding" => voWifiL10n(
    context,
  ).voWifiInvalidSIMCommandEncoding,
  "Invalid Wi-Fi calling response" => voWifiL10n(
    context,
  ).voWifiInvalidWiFiCallingResponse,
  "Invalid incoming SMS segments" => voWifiL10n(
    context,
  ).voWifiInvalidIncomingSMSSegments,
  "SIM response exceeds size limit" => voWifiL10n(
    context,
  ).voWifiSIMResponseExceedsSizeLimit,
  "The SIM reader did not reconnect. Please retry." => voWifiL10n(
    context,
  ).voWifiTheSIMReaderDidNotReconnectPleaseRetry,
  "The SIM reader disconnected. Reconnect it and try Wi-Fi calling again." =>
    voWifiL10n(context).voWifiTheSIMReaderDisconnectedReconnectItAndTryWi,
  "The native engine reported an error" => voWifiL10n(
    context,
  ).voWifiTheNativeEngineReportedAnError,
  "Too many SIM response continuations" => voWifiL10n(
    context,
  ).voWifiTooManySIMResponseContinuations,
  "Unknown Wi-Fi calling callback" => voWifiL10n(
    context,
  ).voWifiUnknownWiFiCallingCallback,
  _ =>
    message.startsWith('SIM status ')
        ? voWifiL10n(context).voWifiSimStatus(message.substring(11))
        : message,
};
