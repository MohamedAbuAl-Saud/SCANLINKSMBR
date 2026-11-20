(function () {
  function readCookie(name) {
    var match = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
    return match ? decodeURIComponent(match[1]) : null;
  }
  try {
    var storedTheme = readCookie('scanlink_theme') || localStorage.getItem('scanlink_theme');
    var theme = storedTheme === 'dark' ? 'dark' : 'light';
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    var metaTheme = document.querySelector('meta[name="theme-color"]');
    if (metaTheme) metaTheme.setAttribute('content', theme === 'dark' ? '#000000' : '#FFFFFF');
    var storedLang = readCookie('scanlink_lang') || localStorage.getItem('scanlink_lang');
    var lang = storedLang === 'ar' ? 'ar' : 'en';
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr';
  } catch (e) {
    document.documentElement.classList.remove('dark');
    document.documentElement.lang = 'en';
    document.documentElement.dir = 'ltr';
  }
})();
