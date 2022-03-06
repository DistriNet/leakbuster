(async function() {
	const clone = (x) => {
		return JSON.parse(JSON.stringify(x));
	}
	const popFromArray = (arr, el) => {
		if (arr.includes(el))
			arr.splice(arr.indexOf(el), 1);
		return arr;
	}

	const arrayEquals = (a, b) => {
	    return Array.isArray(a) &&
	        Array.isArray(b) &&
	        a.length === b.length &&
	        a.every((val, index) => val === b[index]);
	}

	const defenseOptions = {
		"xfo": `Prevent the page to be framed by setting the <code>X-Frame-Options</code> header to <code>DENY</code>, or by using the <code>frame-ancestors</code> directive of CSP.`,
		"coop": `Prevent pages from retaining a reference to your web page when opened in a new tab by setting the <code>Cross-Origin-Opener-Policy</code> header to <code>same-origin</code> or <code>same-origin-allow-popups</code>.`,
		"samesite-lax": `Set the <code>SameSite</code> attribute on authentication cookies to <code>Lax</code> to prevent them to be sent in cross-site requests.`,
		"samesite-strict": false, // has many complications for implementation, so not proposing this here
		"fetch-metadata-rip": `Add restrictions on how requests can be sent by analyzing the Fetch Metadata request headers, and only allow navigational GET requests (commonly referred to as resource isolation policy)`,
		"corp": `Limit how resources can be included in a cross-site context by setting the <code>Cross-Origin-Resource-Policy</code> header to <code>same-origin</code> or <code>same-site</code>.`
	}

	const filters = {
		"xfo": (leak) => {
			if (leak.inclusion_method === 'IF')
				leak.mitigated = true;
			else if (Array.isArray(leak.inclusion_method)) {
				leak.inclusion_method = popFromArray(leak.inclusion_method, 'IF');
				if (leak.inclusion_method.length === 0)
					leak.mitigated = true;
			}
			if (Array.isArray(leak.component)) {
				leak.component = popFromArray(leak.component, 'VI');
			}
			if (leak.component === 'VI' || arrayEquals(leak.component, ['VI']))
				leak.mitigated = true;
			return leak;
		},
		"coop": (leak) => {
			if (leak.inclusion_method === 'WI')
				leak.mitigated = true;
			else if (Array.isArray(leak.inclusion_method)) {
				leak.inclusion_method = popFromArray(leak.inclusion_method, 'WI');
				if (leak.inclusion_method.length === 0)
					leak.mitigated = true;
			}
			if (Array.isArray(leak.component)) {
				leak.component = popFromArray(leak.component, 'VW');
			}
			if (leak.component === 'VW' || arrayEquals(leak.component, ['VW']))
				leak.mitigated = true;

			return leak;
		},
		"coop-unsafe": (leak) => {
			return leak
		},
		"samesite-lax": (leak) => {
			if (['DS', 'DA', 'IF'].includes(leak.inclusion_method)) {
				leak.mitigated = true;
			}
			else if (Array.isArray(leak.inclusion_method)) {
				leak.inclusion_method = popFromArray(leak.inclusion_method, 'IF');
				if (leak.inclusion_method.length === 0)
					leak.mitigated = true;
			}
			// TODO: add note that if inclusion_method is 'WI' or ['WI'], attacks that need POST requests are also mitigated
			return leak;
		},
		"samesite-strict": (leak) => {
			leak.mitigated = true;
			// TODO: verify
			return leak;
		},
		"samesite-default": (leak) => {
			return leak;
		},
		"fetch-metadata-rip": (leak) => {
			if (['DS', 'DA', 'IF'].includes(leak.inclusion_method)) {
				leak.mitigated = true;
			}
			else if (Array.isArray(leak.inclusion_method)) {
				leak.inclusion_method = popFromArray(leak.inclusion_method, 'IF');
				if (leak.inclusion_method.length === 0)
					leak.mitigated = true;
			}
			return leak;
		},
		"corp": (leak) => {
			if (leak.component === 'AP' && ['MD', 'CO'].includes(leak.differentiating_aspect)) {
				if (leak.inclusion_method === 'IF')
					leak.mitigated = true
				else if (Array.isArray(leak.inclusion_method)) {
					leak.inclusion_method = popFromArray(leak.inclusion_method, 'IF');
					if (leak.inclusion_method.length === 0)
						leak.mitigated = true;
				}
			}
			return leak;
		}
	}

	const leakData = await fetch('assets/data/leaks.json');
	const leaksInfo = await leakData.json();
	const leaks = leaksInfo['leaks'];

	const updateLeaks = (leaks, defensesEnabled=[]) => {
		const container = document.getElementById('xsleak-list-container');
		const template = document.getElementById('xsleak-entry-template');

		const suggestionsEl = document.getElementById('xsleak-suggestions');
		const resultsEl = document.getElementById('xsleak-results');
		const successEl = document.getElementById('xsleak-success');
		suggestionsEl.classList.add('d-none');
		resultsEl.classList.add('d-none');
		successEl.classList.add('d-none');

		while (container.firstChild) {
			container.removeChild(container.lastChild);
		}
		for (let leak of leaks) {
			let clonedTemplate = template.content.cloneNode(true);
			clonedTemplate.querySelector('.xsleak-title').textContent = leak.name;
			clonedTemplate.querySelector('.xsleak-description').innerHTML = leak.description.replace('<', '&lt;').replace('>', '&gt;').replace(/`([^`]+)`/g, '<code>$1</code>');
			
			let defenses = [];
			for (let k in filters) {
				if (defensesEnabled.includes(k))
					continue; // defense already enabled
				let mitigated = filters[k](clone(leak)).mitigated;
				if (mitigated)
					defenses.push(k)
			}
			let defenseEls = defenses.filter((defenseName) => {return defenseOptions[defenseName]}).map((defenseName) => {
				let el = document.createElement('li');
				el.classList.add("pb-2");
				el.innerHTML = defenseOptions[defenseName];
				return el;
			});
			if (defenseEls.length > 0) {
				let defensesListEl = clonedTemplate.querySelector('ul.xsleak-possible-defenses-list');
				defenseEls.forEach((el) => {
					defensesListEl.appendChild(el);
				});
			}
			else {
				clonedTemplate.querySelector('.xsleak-possible-defenses').classList.add('d-none');
			}

			let referenceListEl = clonedTemplate.querySelector('ul.xsleak-references-list');
			for (let i = 0; i < leak.reference_urls.length; i++) {
				let el = document.createElement('li');
				el.classList.add("pb-2");
				el.innerHTML = `<a href="${leak.reference_urls[i]}">${leak.reference_titles[i]}</a>`;
				referenceListEl.appendChild(el);
			}

			let browsersListEl = clonedTemplate.querySelector('.browser-icons');
			for (let browser of leak.browsers) {
				browsersListEl.querySelector(`img.${browser}-icon`).classList.remove('disabled');
			}

			container.appendChild(clonedTemplate);
		}

		let suggestions = [];

		if (! defensesEnabled.includes('xfo')) {
			suggestions.push(`Enable framing protection by setting the <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"><code>X-Frame-Options</code> response header</a>, or using the <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors"><code>frame-ancestors</code> directive of CSP</a>. Not only does this protect against clickjacking attacks, preventing other websites from framing your site thwarts a large number of various attacks.`);
		}
		if (! defensesEnabled.includes('coop')) {
			if (defensesEnabled.includes('coop-unsafe')) {
				suggestions.push(`If you are unable to set a safe COOP policy (<code>same-origin</code> or <code>same-origin-allow-popups</code>), ensure that there is as little state-dependent information present on this web page (no frames that are conditionally added, same resources, constant execution time, ...).`);
			}
			else {
				suggestions.push(`Enable the <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy"><code>Cross-Origin-Opener-Policy</code> response header</a>; this prevents other sites from retaining a reference to the window in which your website was opened, and therefore prevents several XS-Leak attacks from being launched. The header is currently only supported by Chromium-based and Gecko-based browsers, i.e. all major browsers except Safari`);
			}
		}
		else {
			suggestions.push(`Make sure that your COOP deployment is consistent and does not depend on the generated, stateful response, otherwise this might still <a href="https://xsleaks.dev/docs/attacks/window-references/">leak information</a> about the state of the user.`);
			if (! defensesEnabled.includes('fetch-metadata-rip') && ! defensesEnabled.includes('samesite-lax') && ! defensesEnabled.includes('samesite-strict')) {
				suggestions.push(`Great that you already enabled COOP! If you would combine this with a <a href="https://web.dev/fetch-metadata/#implementing-a-resource-isolation-policy">Resource Isolation Policy</a> based on the Fetch Metadata request headers or setting the <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"><code>SameSite</code> attribute</a> on your authentication cookies, your website will be protected against all XS-Leak attacks that are known to date.`)
			}
		}
		if (defensesEnabled.includes('fetch-metadata-rip') && ! defensesEnabled.includes('samesite-lax') && ! defensesEnabled.includes('samesite-strict')) {
			suggestions.push(`Well done on implementing a Resource Isolation Policy! If you want to protect Safari users in the same way, consider also setting the <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"><code>SameSite</code> attribute</a> on your authentication cookies.`);
		}
		if (! defensesEnabled.includes('fetch-metadata-rip')) {
			suggestions.push(`Consider implementing a <a href="https://web.dev/fetch-metadata/#implementing-a-resource-isolation-policy">Resource Isolation Policy</a> based on Fetch Metadata request headers; this will effectively block most maliciously-launched cross-site requests and thus thwart a large number of XS-Leak attacks. When combined with COOP, this mitigates all attacks that are known to date. Currently the headers are sent by all major browsers except for Safari.`);
		}
		if (! defensesEnabled.includes('samesite-lax') && ! defensesEnabled.includes('samesite-strict')) {
			suggestions.push(`By setting the <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"><code>SameSite</code> attribute</a> on your authentication cookies to <code>Lax</code> or <code>Strict</code>, you prevent most authenticated cross-site requests to your server and thereby counter several attacks (e.g. XS-Leaks and CSRF). Although Chromium-based browsers have SameSite=Lax enabled by default (although <a href="https://www.chromium.org/updates/same-site/faq#TOC-Q:-What-is-the-Lax-POST-mitigation-">some exceptions exist</a>), it is still highly recommended to explicitly set the <code>SameSite</code> attribute in order to protect users on other browsers.`);
		}
		if (! defensesEnabled.includes('corp')) {
			suggestions.push(`As a defense-in-depth strategy, it can be recommended to set the <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Cross-Origin_Resource_Policy_(CORP)"><code>Cross-Origin-Resource-Policy</code> response header</a>, which indicates to the browsers which resources should not be included in a cross-site context, and will thus prevent any XS-Leaks that rely on parsing responses. This has better cross-browser support than defenses based on Fetch Metadata request headers.`);
		}
		

		if (leaks.length > 0) {
			document.getElementById('xsleak-possible-number').textContent = leaks.length;
			resultsEl.classList.remove('d-none');
		} else {
			successEl.classList.remove('d-none');
		}
		
		if (suggestions.length > 0) {
			const suggestionsListEl = suggestionsEl.querySelector('ul');
			while (suggestionsListEl.firstChild) {
				suggestionsListEl.removeChild(suggestionsListEl.lastChild);
			}
			suggestions.forEach((suggestion) => {
				let el = document.createElement('li');
				el.innerHTML = suggestion;
				suggestionsListEl.appendChild(el);
			});

			suggestionsEl.classList.remove('d-none');
			setTimeout(() => {suggestionsEl.scrollIntoView()}, 200);
		}
		else {
			setTimeout(() => {resultsEl.scrollIntoView()}, 200);
		}
		
	}

	document.getElementById('do-evaluate-button').addEventListener('click', (e) => {
		e.preventDefault();
		let defensesEnabled = [];
		if (['deny', 'same-origin'].includes(document.getElementById('XFOHeaderValue').value)) {
			defensesEnabled.push('xfo');
		}
		if (['same-origin', 'same-origin-allow-popups'].includes(document.getElementById('coopHeaderValue').value)) {
			defensesEnabled.push('coop');
		}
		if (document.getElementById('coopHeaderValue').value === 'unsafe-none') {
			defensesEnabled.push('coop-unsafe');
		}
		if (document.getElementById('sameSiteCookieValue').value === 'lax') {
			defensesEnabled.push('samesite-lax');
		}
		if (document.getElementById('sameSiteCookieValue').value === 'strict') {
			defensesEnabled.push('samesite-strict');
		}
		if (document.getElementById('sameSiteCookieValue').value === 'default') {
			defensesEnabled.push('samesite-default');
		}
		if (document.getElementById('FMHeaderValue').value === 'rip') {
			defensesEnabled.push('fetch-metadata-rip');
		}
		if (['same-site', 'same-origin'].includes(document.getElementById('corpHeaderValue').value)) {
			defensesEnabled.push('corp');
		}

		let filteredLeaks = clone(leaks);
		for (const defense of defensesEnabled) {
			filteredLeaks = filteredLeaks.map(filters[defense]);
		}

		filteredLeaks = filteredLeaks.filter((leak) => {
			return leak.mitigated !== true && leak.show_on_site;
		})

		updateLeaks(filteredLeaks, defensesEnabled);
	})
})();
