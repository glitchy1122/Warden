//! Finance / banking / crypto domains — never inspected by Bloom or custom lists.
//! DNS for these is forwarded upstream immediately (zero blocklist work).

/// Exact hosts (and their subdomains) that always bypass Warden.
const EXACT_BYPASS: &[&str] = &[
    // ── Payments / cards ──────────────────────────────────────────────
    "paypal.com",
    "paypalobjects.com",
    "stripe.com",
    "square.com",
    "squareup.com",
    "venmo.com",
    "cash.app",
    "cashapp.com",
    "wise.com",
    "transferwise.com",
    "revolut.com",
    "klarna.com",
    "afterpay.com",
    "affirm.com",
    "visa.com",
    "visa.com.pk",
    "mastercard.com",
    "americanexpress.com",
    "discover.com",
    "apple.com",
    // Google Pay / Wallet surfaces (not all of Google Search — see INFRA_ALLOW)
    "pay.google.com",
    "payments.google.com",
    // ── Pakistan — commercial banks ───────────────────────────────────
    "hbl.com",
    "hblibank.com.pk",
    "ubl.com.pk",
    "ubldirect.com",
    "meezanbank.com",
    "mcb.com.pk",
    "mcbislamic.com",
    "abl.com",
    "abl.com.pk",
    "bankalfalah.com",
    "alfalah.com",
    "askaribank.com",
    "askari.com.pk",
    "faysalbank.com",
    "jsbl.com",
    "jsbank.com",
    "nbp.com.pk",
    "sbp.org.pk",
    "bop.com.pk",
    "bankofpunjab.com",
    "bankalhabib.com",
    "bah.com.pk",
    "habibmetro.com",
    "habibmetro.com.pk",
    "hmb.com.pk",
    "soneribank.com",
    "soneri.com",
    "bankislami.com.pk",
    "bankislami.com",
    "albaraka.com.pk",
    "albaraka.com",
    "dibpak.com",
    "dib.com.pk",
    "dubaiislamicbank.com.pk",
    "sc.com",
    "standardchartered.com",
    "sc.com.pk",
    "silkbank.com.pk",
    "silkbank.com",
    "summitbank.com.pk",
    "fwbl.com.pk",
    "firstwomenbank.com.pk",
    "bok.com.pk",
    "bankofkhyber.com.pk",
    "ztbl.com.pk",
    "samba.com.pk",
    "sambabank.com",
    "citi.com",
    "citibank.com",
    "citibank.com.pk",
    "idbp.com.pk",
    "idbl.com.pk",
    "punjabcooperativebank.com",
    "ppcb.com.pk",
    "smebank.org",
    "smebank.com.pk",
    "pakoman.com.pk",
    "fcibl.com.pk",
    "pair.com.pk",
    "pairinvestment.com",
    "mobilinkbank.com",
    "telenorbank.pk",
    "u.com.pk",
    "ubank.com.pk",
    "khushhalibank.com.pk",
    "finca.pk",
    "fincamfbpk.com",
    "apnabank.com.pk",
    "nrspbank.com",
    "advanspakistan.com",
    "tameerbank.com",
    "finja.pk",
    "finjapay.com",
    // ── Pakistan — wallets / rails / cards ────────────────────────────
    "jazzcash.com.pk",
    "jazzcash.pk",
    "easypaisa.com.pk",
    "easypaisa.pk",
    "nayapay.com",
    "sadapay.pk",
    "sadapay.com",
    "konnect.pk",
    "keenu.pk",
    "keenu.com.pk",
    "raast.gov.pk",
    "1link.net.pk",
    "1link.com.pk",
    "paypak.pk",
    "paypak.com.pk",
    "kupay.pk",
    "bykea.com",
    "tag.bykea.com",
    // ── US / Canada banks & brokerages ────────────────────────────────
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "capitalone.com",
    "usbank.com",
    "pnc.com",
    "td.com",
    "tdbank.com",
    "truist.com",
    "ally.com",
    "usaa.com",
    "navyfederal.org",
    "schwab.com",
    "fidelity.com",
    "vanguard.com",
    "etrade.com",
    "robinhood.com",
    "interactivebrokers.com",
    "morganstanley.com",
    "goldmansachs.com",
    "jpmorgan.com",
    "jpmorganchase.com",
    "bankofamerica.com",
    "ameritrade.com",
    "tdameritrade.com",
    "merrilledge.com",
    "ml.com",
    "wealthsimple.com",
    "rbc.com",
    "rbcroyalbank.com",
    "scotiabank.com",
    "bmo.com",
    "cibc.com",
    "desjardins.com",
    // ── UK / EU / MENA banks ──────────────────────────────────────────
    "hsbc.com",
    "hsbc.co.uk",
    "barclays.com",
    "barclays.co.uk",
    "barclaycardus.com",
    "lloydsbank.com",
    "lloydsbankinggroup.com",
    "natwest.com",
    "rbs.co.uk",
    "santander.co.uk",
    "santander.com",
    "halifax.co.uk",
    "nationwide.co.uk",
    "monzo.com",
    "starlingbank.com",
    "deutsche-bank.com",
    "db.com",
    "commerzbank.com",
    "ubs.com",
    "credit-suisse.com",
    "bbva.com",
    "ing.com",
    "ing.nl",
    "rabobank.com",
    "bnpparibas.com",
    "societegenerale.com",
    "credit-agricole.com",
    "intesa.com",
    "unicredit.eu",
    "unicreditgroup.eu",
    "nordea.com",
    "danskebank.com",
    "seb.se",
    "swedbank.com",
    "absa.africa",
    "standardbank.co.za",
    "fnb.co.za",
    "nedbank.co.za",
    "emiratesnbd.com",
    "adcb.com",
    "fab.ae",
    "mashreqbank.com",
    "qnb.com",
    "nbk.com",
    "samba.com",
    "alrajhibank.com.sa",
    "riyadbank.com",
    "ncb.com",
    "alahli.com",
    "bankmuscat.com",
    "bankfab.com",
    // ── India / Asia banks (common cross-border) ──────────────────────
    "sbi.co.in",
    "onlinesbi.sbi",
    "hdfcbank.com",
    "icicibank.com",
    "axisbank.com",
    "kotak.com",
    "yesbank.in",
    "pnbindia.in",
    "bankofbaroda.in",
    "unionbankofindia.co.in",
    "paytm.com",
    "phonepe.com",
    "razorpay.com",
    "dbs.com",
    "ocbc.com",
    "uob.com.sg",
    "maybank.com",
    "cimb.com",
    "bca.co.id",
    "mandiri.co.id",
    "bdo.com.ph",
    "bpi.com.ph",
    "commbank.com.au",
    "nab.com.au",
    "westpac.com.au",
    "anz.com",
    "asb.co.nz",
    "bnz.co.nz",
    "mufg.jp",
    "smbc.co.jp",
    "mizuho.com",
    "softbank.jp",
    // ── Crypto exchanges / wallets / infra ────────────────────────────
    "coinbase.com",
    "binance.com",
    "binance.us",
    "kraken.com",
    "gemini.com",
    "crypto.com",
    "blockchain.com",
    "blockchain.info",
    "bitstamp.net",
    "bitfinex.com",
    "kucoin.com",
    "okx.com",
    "bybit.com",
    "bitget.com",
    "gate.io",
    "huobi.com",
    "htx.com",
    "mexc.com",
    "binance.org",
    "metamask.io",
    "walletconnect.com",
    "walletconnect.org",
    "rainbow.me",
    "phantom.app",
    "solflare.com",
    "ledger.com",
    "trezor.io",
    "opensea.io",
    "uniswap.org",
    "aave.com",
    "compound.finance",
    "etherscan.io",
    "bscscan.com",
    "solscan.io",
    "coingecko.com",
    "coinmarketcap.com",
    "tradingview.com",
    "poly.market",
    "polymarket.com",
    "bitpay.com",
    "paxos.com",
    "circle.com",
    "usdc.com",
    "tether.to",
];

/// Everyday infra that must never hit Bloom FPs / ad-block side effects.
/// DoH resolvers stay blocked in `wfp::DOH_HOSTS` (checked first in the DNS path).
const INFRA_ALLOW: &[&str] = &[
    // Google Search / static (Brave & Chrome need these for "internet works")
    "google.com",
    "google.com.pk",
    "gstatic.com",
    "googleapis.com",
    "googleusercontent.com",
    "googlesyndication.com",
    "google-analytics.com",
    "doubleclick.net",
    // YouTube (+ CDNs). Exact youtube.com only for the apex — ads.youtube.com
    // remains bloomable via hosts lists.
    "youtu.be",
    "youtube-nocookie.com",
    "ytimg.com",
    "googlevideo.com",
    "ggpht.com",
    "youtubekids.com",
    // Windows / Brave connectivity
    "microsoft.com",
    "microsoftonline.com",
    "windows.com",
    "windows.net",
    "windowsupdate.com",
    "msftconnecttest.com",
    "msftncsi.com",
    "live.com",
    "office.com",
    "office.net",
    "msn.com",
    "brave.com",
    "bravesoftware.com",
    // Common CDNs (not DNS-over-HTTPS hostnames)
    "cloudflare.com",
    "cloudflareinsights.com",
    "akamaihd.net",
    "akamaized.net",
    "edgekey.net",
    "fastly.net",
    "fastlylb.net",
];

/// Apex hosts allowed exactly (and `www.` only), not every subdomain.
const INFRA_ALLOW_EXACT: &[&str] = &["youtube.com"];

/// Label-level tokens (word-boundary style) — never raw substring of the FQDN.
const TOKEN_BYPASS: &[&str] = &[
    "bank",
    "banking",
    "ibank",
    "ebank",
    "netbanking",
    "paypal",
    "stripe",
    "venmo",
    "wise",
    "revolut",
    "klarna",
    "coinbase",
    "binance",
    "kraken",
    "crypto",
    "bitcoin",
    "ethereum",
    "metamask",
    "broker",
    "brokerage",
    "jazzcash",
    "easypaisa",
    "nayapay",
    "sadapay",
    "raast",
    "paypak",
    "keenu",
    "alhabib",
    "alfalah",
    "meezan",
    "askari",
    "faysal",
    "soneri",
    "islami",
    "albaraka",
    "khushhali",
    "microfinance",
    "mastercard",
    "americanexpress",
    "ledger",
    "trezor",
    "opensea",
    "uniswap",
    "blockchain",
];

#[inline]
pub fn is_finance_bypass(domain: &str) -> bool {
    let d = domain.trim().trim_matches('.').to_ascii_lowercase();
    if d.is_empty() {
        return false;
    }

    for host in EXACT_BYPASS {
        if d == *host || d.ends_with(&format!(".{host}")) {
            return true;
        }
    }

    for host in INFRA_ALLOW {
        if d == *host || d.ends_with(&format!(".{host}")) {
            return true;
        }
    }

    // youtube.com and www.youtube.com only (keeps ads.youtube.com blockable)
    for host in INFRA_ALLOW_EXACT {
        if d == *host || d == format!("www.{host}") {
            return true;
        }
    }

    for label in d.split('.') {
        for token in TOKEN_BYPASS {
            if label_matches_token(label, token) {
                return true;
            }
        }
    }

    false
}

/// Avoid substring traps like "bandwidth" matching "bank".
fn label_matches_token(label: &str, token: &str) -> bool {
    if label == token {
        return true;
    }
    if let Some(rest) = label.strip_prefix(token) {
        if rest.starts_with('-') || rest.starts_with('_') {
            return true;
        }
    }
    if let Some(rest) = label.strip_suffix(token) {
        if rest.ends_with('-') || rest.ends_with('_') {
            return true;
        }
    }
    // meezanbank, askaribank, etc.
    if token == "bank" && label.ends_with("bank") && label.len() > 4 {
        return true;
    }
    label.contains(&format!("-{token}-")) || label.contains(&format!("_{token}_"))
}
