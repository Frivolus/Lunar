# ETAT DU PROJET

> **Lu par l'agent AVANT toute modification. Mis a jour APRES chaque tache.**
> Ne jamais reecrire un fichier existant depuis zero : patcher, completer, ou demander.

## Position

- Phase : 0 — fondations
- Derniere action : payload CRT injecte avec succes, forwarders d'export resolus
- Prochaine action : selection de thread robuste (ignorer les threads bloques, essayer les suivants)

## Fait

- [x] Repo prive cree, arborescence, CMake, .gitignore
- [x] `src/injector` ecrit, compile
- [x] Chemins d'erreur hijack + duree de vie du stub
- [x] Relocations, imports, remap API-set, chargement d'import par chemin
- [x] Resolution des forwarders d'export (sinon DEP dans .edata)
- [x] Table d'exceptions (.pdata) via RtlAddFunctionTable
- [x] TLS : LdrpHandleTlsData + callbacks manuels
- [x] Detour RtlPcToFileHeader
- [x] VEH de diagnostic complet (EXCEPTION_RECORD)
- [x] `--selftest`
- [x] Cible de test `lunar_spin`
- [x] Injection complete du payload brut : DllMain, marqueur, unlink PEB
- [x] Injection complete du payload CRT : DllMain, marqueur, unlink PEB

## Limite connue

Un thread bloque dans un wait noyau (ex. thread principal de `cmd.exe` en attente clavier) ne reprend pas le `RIP` injecte : le changement ne prend effet qu'au retour en mode utilisateur, qui n'arrive pas. Il faut choisir un thread actif ou le reveiller.

## A faire (ordre impose)

- [ ] Selection de thread robuste : detecter les threads bloques, passer au suivant
- [ ] `src/hyperion` : snapshot pages, hook VirtualProtect, anti-debug
- [ ] `src/core` : VM Luau, ScriptContext, identity 7
- [ ] `src/core/api` : 86 fonctions sUNC
- [ ] `tools/dumper` : signature scan
- [ ] `src/launcher` : UI

## Conventions figees

- C++20, x64, MSVC, CMake. Pas de dependance externe non validee.
- Noms : `snake_case` fonctions, `PascalCase` types, `k_` constantes.
- Pas de `CreateRemoteThread` : hijack uniquement.
- Pas de driver noyau.
- Un commit = une brique. Messages en `type: portee - description`.
- Chaque offset passe par `src/core/offsets/offsets.hpp`, jamais en dur ailleurs.

## Decisions

| Date | Decision | Raison |
|---|---|---|
| 30/10/2026 | Repo prive, nom `Lunar` | Pas de fuite, marque courte |
| 30/10/2026 | Payload en 3 binaires (emulator / executor / data) | Patch offsets sans recompiler le signe |
| 30/10/2026 | Injection avant init hyperviseur | Restaurer les hashes apres coup est trop tardif |
| 09/11/2026 | Memoire de travail dans `docs/HANDOFF.md` | Survivre aux compressions |
| 09/11/2026 | Payload brut `/NODEFAULTLIB` comme outil de bisection | Separer un mapper casse d'un CRT non initialise |
| 09/11/2026 | Cible de test `lunar_spin` a thread jamais bloque | Isoler le mapper des threads en wait noyau |
| 09/11/2026 | Voie 1 retenue : rester autonome, pas d'API WeAreDevs | Controle total, x64 |

## Journal

- 30/10/2026 : scaffold, conventions posees, rien de fonctionnel.
- 30/10/2026 : injecteur ecrit, API ntdll resolue dynamiquement.
- 30/10/2026 : compilation verte. DLL de test + CLI --exe/--pid.
- 30/10/2026 : fix signature hijack_call.
- 09/11/2026 : chemins d'erreur hijack, duree de vie du stub.
- 09/11/2026 : TLS, exceptions, detour RtlPcToFileHeader, VEH diagnostic, payload brut.
- 09/11/2026 : cause du timeout identifiee (thread bloque), selftest ajoute, injection bout en bout OK.
- 09/11/2026 : forwarders d'export resolus, payload CRT injecte avec succes.