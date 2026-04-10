class ThemeStore {
  mode = $state<'dark' | 'light'>('dark');

  toggle() {
    this.mode = this.mode === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', this.mode);
  }
}

export const theme = new ThemeStore();
