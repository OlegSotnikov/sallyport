# macOS UI conventions

Shared tokens and components live in `Sources/SallyportApp/Theme.swift`.

## Tokens

- Spacing: `Theme.Spacing` with 2, 4, 8, 12, 16, 20, and 24 point steps.
- Screen inset: `Theme.screenPadding`.
- Radius: `Theme.Radius.sm`, `md`, `lg`, and `xl`.
- Typography: use `Theme.Typography` roles instead of ad hoc font choices.
- Color: `Theme.accent`, `verified`, `warning`, and `danger`.
- Surfaces: `Theme.Surface.card`, `stroke`, `inset`, `hover`, `pressed`, and `selection`.

Use native materials for sidebar and toolbar chrome. Use solid card surfaces for content. The approval card is the only elevated card.

## Components

| Component | Use |
|---|---|
| `ScreenHeader` | screen title, subtitle, symbol, and optional action |
| `Card` / `.card()` | grouped content |
| `SectionHeader` | section label inside a screen or card |
| `KeyValueRow` | aligned read-only label and value |
| `StatusPill` / `DecisionBadge` | state and decision labels |
| `EmptyStateView` | empty content with optional actions |
| `LockedVaultView` | locked data screens |
| `LoadingSkeleton` | initial loading state |
| `ErrorBanner` | recoverable inline error with retry |
| `FormRow`, `TokenEditor`, `FlowChips`, `SheetButtons` | management forms |

## Screen structure

Use this order:

1. `ScreenHeader`.
2. Divider.
3. Scrollable content.
4. Cards and section headers.

Management screens use `ManagementScaffold`, which owns locked, loading, error, toolbar, and content states.

Do not render stale sealed data while locked. Hide data actions and show `LockedVaultView` with Unlock.

## Interaction

- Use `.borderedProminent` for the primary action and `.bordered` for secondary actions.
- Provide hover, pressed, selected, disabled, loading, empty, and error states where applicable.
- Keep destructive actions behind a confirmation dialog.
- Keep technical error detail behind disclosure when the user-facing message is enough.
- Use a full-width hit target for selectable rows.

## Approval cards

Cards show:

- process or app identity;
- code-signing authority and provenance state;
- requested tool, target, and summary;
- why approval is required;
- Deny and Approve actions.

An invalid provenance chain changes the border and warning treatment. Session cards authorize the live process; per-call cards authorize one call. Touch ID is used only for modes that require it. The current engine does not provide danger-token annotations.

There are no grant-duration controls or persist chips.

## Previews

Add light and dark `#Preview` coverage for new screens and important component states. Use `AppModel.previewModel()` or the relevant mock view model. Previews must not require a real vault, daemon, or Touch ID.

Run `swift test` after changing shared UI logic. Use the rendered app for final layout and accessibility checks.
