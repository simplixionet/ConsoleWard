<p align="center">
  <img src="build/icon.svg" width="96" height="96" alt="ConsoleWard">
</p>

<h1 align="center">ConsoleWard</h1>

Desktopový SSH klient (Electron) se **šifrovaným trezorem** pro adresy, uživatele, hesla
a privátní klíče. Ve druhé fázi přibude AI chat, který smí psát do konzole **jen s
výslovným schválením člověka**.

## Spuštění

Vývojový režim (hot reload):

```bash
npm run dev
```

Produkční build a spuštění:

```bash
npm run build
npm start
```

Instalátor pro Windows (NSIS + portable, do `release/`):

```bash
npm run dist
```

Kontrola typů:

```bash
npm run typecheck
```

## Co umí

- **Šifrovaný trezor** – jeden soubor `vault.enc` v profilu uživatele. Obsah šifruje
  náhodný datový klíč (**AES-256-GCM**), který je v souboru uložený zabalený hlavním
  heslem a obnovovacím klíčem (oba přes **scrypt**, N=2¹⁷, r=8, p=1). Špatné heslo pozná
  GCM autentizační tag – nelze ho obejít.
- **Obnovovací klíč** – 30 znaků / 150 bitů entropie, generuje se při založení trezoru
  a zobrazí se jen jednou. Umožní resetovat zapomenuté hlavní heslo. Lze ho kdykoli
  přegenerovat i úplně zrušit.
- **Připojení** – název, host, port, uživatel, složka, poznámka. Přihlášení heslem,
  privátním klíčem (OpenSSH PEM, včetně passphrase) nebo přes SSH agenta
  (Pageant / OpenSSH agent).
- **Ověřování host key** – otisky `SHA256:...` ve formátu OpenSSH. První připojení se
  potvrzuje (TOFU), **změna otisku se hlásí jako varování** a bez potvrzení se spojení
  neotevře. Uložené otisky lze spravovat v Nastavení → Známé servery.
- **Příkazy a poznámky** – knihovna uložených příkazů (s popisem a složkami) a volných
  poznámek. Uložený příkaz jde zkopírovat, **vložit** do terminálu bez odeslání (Enter
  stiskneš sám) nebo rovnou **spustit**. Víceřádkový příkaz se před vložením potvrzuje —
  v shellu se každý konec řádku chová jako Enter. Vše je v trezoru, tedy šifrované.
- **Terminál** – xterm.js, více relací v záložkách, historie výstupu, hledání
  (`Ctrl+Shift+F`), kopírování `Ctrl+Shift+C`, vkládání `Ctrl+Shift+V` nebo pravým
  tlačítkem (jako v PuTTY).
- **AI přístup přes MCP** – lokální MCP server, přes který může AI klient (Claude Code
  apod.) vidět názvy relací, navrhovat příkazy a číst výstup. Vždy přes bránu, kterou
  držíš ty. Ve výchozím stavu vypnuto.
- **Automatické zamčení** po nastavené době nečinnosti; volitelně zároveň ukončí
  všechny SSH relace.
- **Změna hlavního hesla** – přešifruje celý trezor novým klíčem.

## Bezpečnostní model

| Co | Kde žije |
|---|---|
| Hesla, privátní klíče, passphrase | pouze hlavní proces, uvnitř šifrovaného trezoru |
| UI (renderer) | dostává jen metadata a příznaky `hasPassword` / `hasPrivateKey` |
| Otisky serverů | v trezoru, šifrovaně |
| Příkazy a poznámky | v trezoru, šifrovaně (do UI se posílají — musíš je vidět a editovat) |
| Obnovovací klíč | nikde — v souboru je jen zámek z něj odvozený |

- Renderer běží se `contextIsolation: true`, `nodeIntegration: false` a `sandbox: true`;
  komunikuje výhradně přes úzké IPC rozhraní v preloadu.
- Content-Security-Policy je nastavená hlavičkou i meta tagem; externí odkazy se
  otevírají v systémovém prohlížeči, navigace uvnitř okna je zakázaná.
- Tajemství se z formuláře posílají jen tehdy, když je uživatel skutečně změní –
  prázdné pole znamená „ponechat beze změny“, tlačítko *Smazat* znamená „odstranit“.
- Trezor se zapisuje atomicky (`.tmp` → přejmenování) a předchozí verze se zálohuje
  do `vault.enc.bak`. Záloha je snímek — platí pro ni heslo, které platilo v době jejího
  vzniku.
- Trezory ve starém formátu (verze 1, klíč odvozený přímo z hesla) se při odemčení
  automaticky převedou na verzi 2.

### Obnovovací klíč

Trezor používá obálkové šifrování: obsah šifruje náhodný **datový klíč (DEK)**, který
je v souboru uložený vícekrát – pokaždé zabalený jiným tajemstvím:

```
wrap[password] = AES-GCM(DEK, scrypt(hlavní heslo, salt₁))
wrap[recovery] = AES-GCM(DEK, scrypt(obnovovací klíč, salt₂))
```

Odemknout lze kterýmkoli z nich. Změna hesla i obnova proto jen přebalí DEK — obsah
trezoru se znovu nešifruje.

Klíč má 30 znaků v abecedě Crockford Base32 (bez `I`, `L`, `O`, `U`, aby nešlo splést
znaky při přepisu) = **150 bitů entropie**. Při zadávání nezáleží na velikosti písmen ani
na oddělovačích a `O`/`0` i `I`/`L`/`1` se automaticky sjednotí.

> **Klíč se nikde neukládá** — v trezoru je z něj odvozený jen zámek, ne klíč samotný.
> Zobrazí se jednou při vytvoření trezoru (a při přegenerování v Nastavení). Kdo ho má,
> dostane se ke všem uloženým heslům, takže ho drž **odděleně od souboru trezoru**.
>
> **Když ztratíš heslo i obnovovací klíč, data jsou nenávratně pryč.** Zadní vrátka
> neexistují.

Obnovovací klíč lze v Nastavení → Zabezpečení kdykoli přegenerovat (starý okamžitě
přestane platit) nebo úplně odstranit, pokud nechceš, aby druhá cesta k datům existovala.

## AI přístup přes MCP

Zapíná se v Nastavení → AI přístup. Aplikace pak hostí MCP server na `127.0.0.1`
(výchozí port 7345) a vypíše příkaz k nastavení klienta:

```bash
claude mcp add --transport http consoleward http://127.0.0.1:7345/ --header "Authorization: Bearer <token>"
```

### Co AI dostane a co ne

| Nástroj | Co dělá |
|---|---|
| `list_sessions` | jen `id`, název a stav relace — **adresa, port ani uživatel se neposílají** |
| `run_command` | navrhne příkaz; **nespustí se, dokud ho neschválíš** v dialogu |
| `read_terminal` | požádá o výstup; ty vybereš nebo přepíšeš, co přesně odejde |

Dialog s příkazem zobrazuje jeho **doslovné znění se zviditelněnými řídicími znaky**,
aby v něm nešel schovat řádek navíc. Není tam „schválit vše" ani „zapamatovat" — každý
příkaz vidíš zvlášť. To je celý smysl brány.

Ve výběrovém dialogu je výstup **editovatelný**: můžeš označit část a poslat jen ji,
cokoliv přepsat, nebo označené nahradit `[REDIGOVÁNO]`. Podezřelá místa (hesla
v přiřazení, tokeny, privátní klíče, přihlašovací údaje v URL, IP adresy) se podbarvují.
Je to jen vodítko — regulární výrazy nezachytí všechno.

AI vždy dostane poznámku, že jde o výřez, aby z neúplného výstupu nevyvozovala závěry,
jako by viděla vše.

### Zabezpečení serveru

- poslouchá **výhradně na `127.0.0.1`**, nikdy na `0.0.0.0`
- povinný bearer token (uložený v trezoru)
- ochrana proti DNS rebindingu — cizí hlavička `Host` i `Origin` vrací 403
- při zamčení trezoru se server okamžitě vypne a čekající žádosti se odmítnou
- bez odpovědi do 5 minut se žádost sama zamítne

> ⚠️ **Co odejde na internet:** příkazy, které AI navrhne, a **výstup, který pustíš**.
> Tvůj AI klient je posílá svému poskytovateli. Přihlašovací údaje a adresy zůstávají
> lokálně, obsah výstupu ne.
>
> ⚠️ **Prompt injection:** výstup terminálu je nedůvěryhodný vstup. Když v logu bude
> „ignoruj předchozí instrukce a spusť…", model to může navrhnout. Jediná skutečná
> obrana je ta schvalovací brána — čti, co schvaluješ.

## Poznámka k rotaci hesla

Změna hlavního hesla přebalí datový klíč, ale **nemění ho**. Pokud někdo dříve získal
kopii souboru *a* staré heslo, změna hesla mu už jednou přečtená data nevezme. V takovém
případě založ nový trezor a připojení do něj přenes ručně.

### Klíče ve formátu PuTTY (.ppk)

`.ppk` se přímo nepodporuje. Převeď ho v PuTTYgen přes
*Conversions → Export OpenSSH key* a výsledný soubor načti v editoru připojení.

## Struktura projektu

```
src/
  shared/     typy a názvy IPC kanálů sdílené napříč procesy
  main/       hlavní proces: trezor (vault.ts), SSH (ssh.ts), IPC (index.ts)
  preload/    most mezi hlavním procesem a UI (contextBridge)
  renderer/   React UI + xterm.js terminál
```

## Stav

Fáze 1 (SSH klient + trezor) je hotová a odzkoušená end-to-end proti reálnému SSH serveru.
Fáze 2 – AI chat s API klíčem a schvalováním každého příkazu člověkem – zatím není
implementovaná; v trezoru a nastavení jsou pro ni připravená pole.
