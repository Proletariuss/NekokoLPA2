import '../services/local_notification_service.dart';

abstract interface class VoWifiNotifications {
  Future<bool> requestPermission();

  Future<void> showIncoming({required int messageId, required String lineKey});
}

class LocalVoWifiNotifications implements VoWifiNotifications {
  const LocalVoWifiNotifications();

  @override
  Future<bool> requestPermission() =>
      LocalNotificationService().requestVoWifiSmsPermission();

  @override
  Future<void> showIncoming({
    required int messageId,
    required String lineKey,
  }) => LocalNotificationService().showVoWifiSms(
    messageId: messageId,
    lineKey: lineKey,
  );
}
