/// Presentation-only grouping; never merges conversations from different SIMs.
class VoWifiConversation {
  VoWifiConversation(this.lineKey, this.peer);
  final String lineKey;
  final String peer;
  final List<Map<String, Object?>> messages = [];
}

List<VoWifiConversation> groupVoWifiMessages(
  List<Map<String, Object?>> messages,
) {
  final groups = <(String, String), VoWifiConversation>{};
  for (final message in messages) {
    final line = message['line_key'] as String? ?? '';
    final peer = message['peer'] as String? ?? '';
    final group = groups.putIfAbsent((
      line,
      peer,
    ), () => VoWifiConversation(line, peer));
    group.messages.add(message);
  }
  for (final group in groups.values) {
    group.messages.sort(
      (a, b) => (b['at'] as String? ?? '').compareTo(a['at'] as String? ?? ''),
    );
  }
  return groups.values.toList()..sort(
    (a, b) => (b.messages.first['at'] as String? ?? '').compareTo(
      a.messages.first['at'] as String? ?? '',
    ),
  );
}
