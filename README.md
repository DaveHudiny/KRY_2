# Implementace SHA256 a extension length útoku

Tato složka obsahuje řešení druhého projektu z předmětu kryptografie na VUT FIT. Zadáním je implementovat algoritmus SHA256 dle původní dokumentace, a to s možností jednak udělat samotný hash, vytvořit MAC na základě hash(Heslo + Zpráva), verifikovat tento MAC vůči tajnému heslu a na závěr implementovat extension length attack, který umožňuje odesílat zprávy, které jsou správně zahashovány, aniž bychom měli původní klíč.

Struktura projektu je jednoduchá -- obsahuje pouze soubory kry.cpp a kry.hpp s implementací všech kódů, kde ke každé úloze je přiřazena vlastní funkce volaná z větvení ve funkci do_stuff. Kromě samotného řešení obsahuje i pár funkcí na debuggování, které nejsou v odevzdávaném projektu nikde volány, ale byly v rámci tvorby projektu využity (vlastní tvorba).

V rámci řešení projektu byly v rámci souboru hpp zahrnuty následující knihovny:
 - iostream
 - getopt.h
 - string.h
 - gmp.h
 - regex
 - bitset
 - iomanip
které byly ve výsledném řešení do různé míry využity. Všechny by měly být k dispozici v rámci standardního balíku C++.

Tímto se autor projektu, David Hudák (xhudak03@vutbr.cz), že projekt byl vypracován samostatně a bez využití velkých jazykových modelů a že nebylo využito jiných zdrojů, než které jsou uvedeny v zadání projektu a oficiálních zdrojů týkajících se použitých knihoven.

## Technické detaily

Vstupní řetězec je zpracováván s pomocí datového typu string, načež v rámci hashování je rozdělen na jednotlivá slova typu uint32_t zahrnutá v dynamické datové struktuře v C++, std:vector. Tato slova jsou pak součástí dílčích podvektorů, které jsou předávány funkci process\_block(), jejíž účelem je provádění kroků tak, jak jsou uvedeny v dokumentaci.

Projekt byl testován jednak vůči přikladům uvedeným v zadání projektu, jednak na několika "náhodných" řetězcích jako jsou "ahoj\_svete", "ahoj\_svete" akorát několikrát za sebou (aby se nevešly do jednoho bloku) apod. a srovnáván byl s Linuxovou implementací sha256sum. Jediný známý bug, který implementace obsahuje, je způsobem občasnou nekompatibilitou getopt a sanitizérů, kdy při volání programu například s ./kry -a sanitizéry zabijí getopt (nejspíše špatná práce s absencí argumentu, kterou v projektu řeším pouze použitím volání getoptu "a:"). Projekt byl testován lokálně na aktualizovaném Ubuntu a bez použití sanitizérů na serveru Merlin.

