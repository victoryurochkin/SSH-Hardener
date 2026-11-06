using System.ComponentModel;
using System.Globalization;
using System.Resources;

namespace SSHHardener.App;

public sealed class Localization : INotifyPropertyChanged
{
    private readonly ResourceManager _resources = new("SSHHardener.App.Resources.Strings", typeof(Localization).Assembly);
    private CultureInfo _culture = CultureInfo.GetCultureInfo("ru");
    public string this[string key] => _resources.GetString(key, _culture) ?? key;
    public bool English => _culture.TwoLetterISOLanguageName == "en";
    public void Toggle()
    {
        _culture = CultureInfo.GetCultureInfo(English ? "ru" : "en");
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));
    }
    public event PropertyChangedEventHandler? PropertyChanged;
}
