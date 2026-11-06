# WPF apply-log regression

This is a small Windows STA executable, with no new NuGet dependencies. It constructs a plain `Application`, loads the actual linked `App.xaml` resources, and shows the real `MainWindow` outside the visible desktop. It uses the production `MainViewModel.Log` binding and private `AddLog` path, with fake SSH/audit/plan/engine dependencies. Production `App.OnStartup` and its MessageBox exception handler never run; no network connection, user profile or credential is used.

Run from the checkout root:

```powershell
dotnet run --project tests/SSHHardener.UiTests/SSHHardener.UiTests.csproj -c Release -- artifacts/ui-regression-fixed.txt
```

The executable exits nonzero for a synchronous or dispatcher exception, stale list binding, broken 1000-entry trim, lost progress or missing final autoscroll. It also checks tab switching, collection reset and closing with a pending scroll. A controlled operation verifies that fatal UI failure cancels immediately, waits for explicitly released independent recovery, blocks concurrent work and keeps the model disabled afterward. Its diagnostics file contains the failing stage and stack trace, without displaying an error dialog.

For a controlled demonstration of the previous failure, run:

```powershell
dotnet run --project tests/SSHHardener.UiTests/SSHHardener.UiTests.csproj -c Release -- --legacy-scroll artifacts/ui-regression-legacy.txt
```

This intentionally reinstalls the old synchronous `CollectionChanged → ScrollIntoView` callback before the ItemsSource subscription. It is expected to exit **1** with an ItemsControl/ItemContainerGenerator inconsistency during the initial log burst. It does not edit production code. The normal command is the regression check to run in CI; the legacy command is a diagnostic baseline and must not be treated as a passing test.
