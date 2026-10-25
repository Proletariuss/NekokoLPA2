import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:nlpa2/vowifi/apdu_exchange.dart';

void main() {
  test('preserves exact commands and reassembles GET RESPONSE data', () async {
    final sent = <List<int>>[];
    final replies = [
      [1, 2, 0x61, 2],
      [3, 0x61, 1],
      [4, 0x90, 0],
    ];
    final exchange = VoWifiApduExchange((command) async {
      sent.add(command.toList());
      return Uint8List.fromList(replies.removeAt(0));
    });
    expect(await exchange.exchange(['00b0000009']), ['010203049000']);
    expect(sent, [
      [0, 0xb0, 0, 0, 9],
      [0, 0xc0, 0, 0, 2],
      [0, 0xc0, 0, 0, 1],
    ]);
  });

  test('corrects Le on 6C without changing case 4 command data', () async {
    final sent = <List<int>>[];
    final exchange = VoWifiApduExchange((command) async {
      sent.add(command.toList());
      return Uint8List.fromList(sent.length == 1 ? [0x6c, 3] : [0x90, 0]);
    });
    await exchange.exchange(['00a40000023f0000']);
    expect(sent.last, [0, 0xa4, 0, 0, 2, 0x3f, 0, 3]);
  });

  test('bounds continuation loops', () async {
    var count = 0;
    final exchange = VoWifiApduExchange((_) async {
      count++;
      return Uint8List.fromList([0x61, 0]);
    });
    await expectLater(exchange.exchange(['00b0000009']), throwsStateError);
    expect(count, 32);
  });

  test('aborts the batch after a failed status word', () async {
    var count = 0;
    final exchange = VoWifiApduExchange((_) async {
      count++;
      return Uint8List.fromList([0x69, 0x82]);
    });
    await expectLater(
      exchange.exchange(['00a40000023f00', '00b0000009']),
      throwsA(
        isA<StateError>().having(
          (error) => error.message,
          'message',
          'SIM status 6982',
        ),
      ),
    );
    expect(count, 1);
  });

  test('rejects malformed commands before sending any APDU', () async {
    var count = 0;
    final exchange = VoWifiApduExchange((_) async {
      count++;
      return Uint8List.fromList([0x90, 0]);
    });
    await expectLater(
      exchange.exchange(['00b0000009', 'bad']),
      throwsFormatException,
    );
    expect(count, 0);
  });

  test('rejects stale reader generations', () async {
    var count = 0;
    final exchange = VoWifiApduExchange((_) async {
      count++;
      return Uint8List.fromList([0x90, 0]);
    }, isCurrent: () => false);
    await expectLater(exchange.exchange(['00b0000009']), throwsStateError);
    expect(count, 0);
  });
}
