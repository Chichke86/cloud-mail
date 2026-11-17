try {
	const dark = JSON.parse(localStorage.getItem('ui'))?.dark;
	document.documentElement.classList.toggle('dark', Boolean(dark));
	const mobile = !window.matchMedia('(pointer: fine) and (hover: hover)').matches;
	document.getElementById('theme-color-meta').content =
		dark ? (mobile ? '#141414' : '#000000') : (mobile ? '#FFFFFF' : '#F1F1F1');
} catch {
	// Invalid legacy UI preferences should not prevent the app from loading.
}
