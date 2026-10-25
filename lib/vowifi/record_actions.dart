import 'l10n.dart';
import 'package:flutter/material.dart';

class RecordSelection extends ChangeNotifier {
  bool editing = false;
  bool busy = false;
  final selected = <int>{};
  bool _disposed = false;
  int _scopeGeneration = 0;

  void clear() {
    if (_disposed) return;
    _scopeGeneration++;
    selected.clear();
    notifyListeners();
  }

  void retain(Set<int> ids) {
    if (_disposed || ids.containsAll(selected)) return;
    selected.retainAll(ids);
    _scopeGeneration++;
    notifyListeners();
  }

  void toggleMode() {
    if (_disposed || busy) return;
    editing = !editing;
    clear();
  }

  void toggle(Set<int> ids) {
    if (_disposed || busy || ids.isEmpty) return;
    if (selected.containsAll(ids)) {
      selected.removeAll(ids);
    } else {
      selected.addAll(ids);
    }
    notifyListeners();
  }

  Future<void> perform(
    BuildContext context,
    Set<int> ids,
    Future<void> Function(Set<int>) action, {
    bool deleting = false,
  }) async {
    if (_disposed || busy || ids.isEmpty || !context.mounted) return;
    final snapshot = Set<int>.unmodifiable(ids);
    final generation = _scopeGeneration;
    busy = true;
    notifyListeners();
    try {
      if (deleting) {
        final yes = await showDialog<bool>(
          context: context,
          builder: (context) => AlertDialog(
            title: Text(voWifiL10n(context).voWifiDeleteRecords),
            content: Text(
              voWifiL10n(context).voWifiDeleteRecordCount(snapshot.length),
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context, false),
                child: Text(voWifiL10n(context).voWifiCancel),
              ),
              TextButton(
                onPressed: () => Navigator.pop(context, true),
                child: Text(voWifiL10n(context).voWifiDelete),
              ),
            ],
          ),
        );
        if (yes != true) return;
      }
      if (_disposed || !context.mounted || generation != _scopeGeneration) {
        return;
      }
      await action(snapshot);
      if (!_disposed) selected.removeAll(snapshot);
    } catch (_) {
      if (!_disposed && context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              voWifiL10n(context).voWifiCouldNotUpdateRecordsTryAgain,
            ),
          ),
        );
      }
    } finally {
      busy = false;
      if (!_disposed) notifyListeners();
    }
  }

  @override
  void dispose() {
    _disposed = true;
    super.dispose();
  }
}

Widget recordToolbar(
  BuildContext context,
  RecordSelection selection,
  Set<int> ids,
  Future<void> Function(Set<int>) remove,
) {
  final visibleSelected = selection.selected.intersection(ids);
  return Padding(
    padding: const EdgeInsets.symmetric(horizontal: 16),
    child: Wrap(
      spacing: 12,
      crossAxisAlignment: WrapCrossAlignment.center,
      children: [
        TextButton(
          onPressed: selection.busy ? null : selection.toggleMode,
          child: Text(
            selection.editing
                ? voWifiL10n(context).voWifiDone
                : voWifiL10n(context).voWifiEdit,
          ),
        ),
        if (selection.editing) ...[
          Text(
            voWifiL10n(
              context,
            ).voWifiSelectedRecordCount(visibleSelected.length),
          ),
          TextButton(
            onPressed: selection.busy || ids.isEmpty
                ? null
                : () => selection.toggle(ids),
            child: Text(
              ids.isNotEmpty && selection.selected.containsAll(ids)
                  ? voWifiL10n(context).voWifiDeselectAll
                  : voWifiL10n(context).voWifiSelectAll,
            ),
          ),
          TextButton(
            onPressed: selection.busy || visibleSelected.isEmpty
                ? null
                : () => selection.perform(
                    context,
                    visibleSelected,
                    remove,
                    deleting: true,
                  ),
            child: Text(voWifiL10n(context).voWifiDeleteSelected),
          ),
        ],
      ],
    ),
  );
}

Widget recordSwipe(
  BuildContext context, {
  required String identity,
  required Set<int> ids,
  required bool unread,
  required RecordSelection selection,
  required Future<void> Function(Set<int>) read,
  required Future<void> Function(Set<int>) remove,
  required Widget child,
}) {
  if (ids.isEmpty) return child;
  return Dismissible(
    key: ValueKey('record-$identity'),
    direction: selection.busy || selection.editing
        ? DismissDirection.none
        : DismissDirection.horizontal,
    background: Container(
      color: Colors.red,
      alignment: Alignment.centerLeft,
      padding: const EdgeInsets.all(20),
      child: Text(
        voWifiL10n(context).voWifiDelete,
        style: TextStyle(color: Colors.white),
      ),
    ),
    secondaryBackground: Container(
      color: Colors.blue,
      alignment: Alignment.centerRight,
      padding: const EdgeInsets.all(20),
      child: Text(
        voWifiL10n(context).voWifiRead,
        style: TextStyle(color: Colors.white),
      ),
    ),
    confirmDismiss: (direction) async {
      await selection.perform(
        context,
        ids,
        direction == DismissDirection.endToStart ? read : remove,
        deleting: direction == DismissDirection.startToEnd,
      );
      return false;
    },
    child: Row(
      children: [
        if (selection.editing)
          Checkbox(
            value: selection.selected.containsAll(ids),
            onChanged: selection.busy ? null : (_) => selection.toggle(ids),
          )
        else if (unread)
          const Padding(
            padding: EdgeInsets.only(right: 6),
            child: Icon(Icons.circle, size: 8, color: Colors.blue),
          ),
        Expanded(
          child: selection.editing
              ? GestureDetector(
                  behavior: HitTestBehavior.opaque,
                  onTap: selection.busy ? null : () => selection.toggle(ids),
                  child: IgnorePointer(child: child),
                )
              : child,
        ),
      ],
    ),
  );
}
