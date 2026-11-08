// Loaded before first paint so a saved theme never flashes. A cookie, because the random port gives localStorage a new origin on every run.
const savedTheme = document.cookie.match(/(?:^|; )mucha-theme=(light|dark)/)?.[1];
if (savedTheme) document.documentElement.dataset.theme = savedTheme;
