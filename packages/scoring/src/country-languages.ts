// Main languages (ISO 639-1) people browse in, per country. Hand-written and deliberately generous:
// it only feeds the display-only "language vs IP country" row, so a missing language costs nothing.
const TABLE: Record<string, string> = {
  AD: 'ca es fr', AE: 'ar en', AF: 'fa ps', AG: 'en', AL: 'sq', AM: 'hy ru', AO: 'pt', AR: 'es', AT: 'de', AU: 'en',
  AZ: 'az ru', BA: 'bs hr sr', BB: 'en', BD: 'bn', BE: 'nl fr de', BF: 'fr', BG: 'bg', BH: 'ar en', BI: 'fr rn', BJ: 'fr',
  BN: 'ms en', BO: 'es', BR: 'pt', BS: 'en', BT: 'dz en', BW: 'en tn', BY: 'be ru', BZ: 'en es', CA: 'en fr', CD: 'fr',
  CF: 'fr', CG: 'fr', CH: 'de fr it rm', CI: 'fr', CL: 'es', CM: 'fr en', CN: 'zh', CO: 'es', CR: 'es', CU: 'es',
  CV: 'pt', CY: 'el tr en', CZ: 'cs', DE: 'de', DJ: 'fr ar', DK: 'da', DM: 'en', DO: 'es', DZ: 'ar fr', EC: 'es',
  EE: 'et ru', EG: 'ar', ER: 'ti ar en', ES: 'es ca gl eu', ET: 'am', FI: 'fi sv', FJ: 'en', FR: 'fr', GA: 'fr', GB: 'en cy',
  GD: 'en', GE: 'ka ru', GH: 'en', GM: 'en', GN: 'fr', GQ: 'es fr', GR: 'el', GT: 'es', GW: 'pt', GY: 'en',
  HK: 'zh en', HN: 'es', HR: 'hr', HT: 'fr ht', HU: 'hu', ID: 'id', IE: 'en ga', IL: 'he ar', IN: 'hi en bn te mr ta ur gu kn ml pa',
  IQ: 'ar ku', IR: 'fa', IS: 'is', IT: 'it', JM: 'en', JO: 'ar', JP: 'ja', KE: 'en sw', KG: 'ky ru', KH: 'km',
  KM: 'ar fr', KN: 'en', KP: 'ko', KR: 'ko', KW: 'ar', KZ: 'kk ru', LA: 'lo', LB: 'ar fr', LC: 'en', LI: 'de',
  LK: 'si ta', LR: 'en', LS: 'en st', LT: 'lt', LU: 'lb fr de', LV: 'lv ru', LY: 'ar', MA: 'ar fr', MC: 'fr', MD: 'ro ru',
  ME: 'sr', MG: 'mg fr', MK: 'mk sq', ML: 'fr', MM: 'my', MN: 'mn', MO: 'zh pt', MR: 'ar', MT: 'mt en', MU: 'en fr',
  MV: 'dv', MW: 'en', MX: 'es', MY: 'ms en zh', MZ: 'pt', NA: 'en af', NE: 'fr', NG: 'en', NI: 'es', NL: 'nl',
  NO: 'nb nn no', NP: 'ne', NZ: 'en mi', OM: 'ar', PA: 'es', PE: 'es', PG: 'en', PH: 'en tl fil', PK: 'ur en', PL: 'pl',
  PR: 'es en', PS: 'ar', PT: 'pt', PY: 'es gn', QA: 'ar', RO: 'ro', RS: 'sr', RU: 'ru', RW: 'rw fr en', SA: 'ar',
  SB: 'en', SC: 'en fr', SD: 'ar en', SE: 'sv', SG: 'en zh ms ta', SI: 'sl', SK: 'sk', SL: 'en', SM: 'it', SN: 'fr',
  SO: 'so ar', SR: 'nl', SS: 'en', SV: 'es', SY: 'ar', SZ: 'en ss', TD: 'fr ar', TG: 'fr', TH: 'th', TJ: 'tg ru',
  TL: 'pt', TM: 'tk ru', TN: 'ar fr', TO: 'en to', TR: 'tr', TT: 'en', TW: 'zh', TZ: 'sw en', UA: 'uk ru', UG: 'en sw',
  US: 'en es', UY: 'es', UZ: 'uz ru', VC: 'en', VE: 'es', VN: 'vi', VU: 'bi en fr', WS: 'sm en', YE: 'ar', ZA: 'en af zu xh',
  ZM: 'en', ZW: 'en sn',
};

/** Languages of a country, or null when the table doesn't know it. */
export function countryLanguages(cc: string | null): string[] | null {
  return (cc && TABLE[cc.toUpperCase()]?.split(' ')) || null;
}
