import 'package:flutter_test/flutter_test.dart';
import 'package:nlpa2/vowifi/conversations.dart';

void main() {
  test('same peer on different SIMs stays isolated and newest comes first', () {
    final groups = groupVoWifiMessages([
      {'line_key': 'a', 'peer': '888', 'at': '2026-10-09T01:00:00Z'},
      {'line_key': 'b', 'peer': '888', 'at': '2026-10-09T03:00:00Z'},
      {'line_key': 'a', 'peer': '888', 'at': '2026-10-09T02:00:00Z'},
    ]);
    expect(groups.length, 2);
    expect(groups.first.lineKey, 'b');
    expect(groups.last.messages.length, 2);
    expect(groups.last.messages.first['at'], '2026-10-09T02:00:00Z');
  });
}
