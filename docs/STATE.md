# ETAT DU PROJET

> **Lu par l'agent AVANT toute modification. Mis a jour APRES chaque tache.**
> Ne jamais reecrire un fichier existant depuis zero : patcher, completer, ou demander.

## Position

- Phase : 0 — fondations
- Derniere action : WIP de debug commite (TLS, exceptions, detour RtlPcToFileHeader, VEH diagnostic, payload brut /NODEFAULTLIB)
- Prochaine action : injecter le payload brut dans notepad.exe pour isoler mapper vs CRT

## Fait

- [x] Repo prive cree
- [x] Arborescence src/ injector / hyperion / core / launcher
- [x] CMake racine + sous-projets vides
- [x] .gitignore Visual Studio + CMake
- [x] `src/injector` ecrit, compile
- [x] Chemins d'erreur hijack + duree de vie du stub
- [x] Relocations, imports, remap API-set, chargement d'import par chemin
- [x] Table d'exceptions (.pdata) via RtlAddFunctionTable
- [x] TLS : LdrpHandleTlsData + callbacks manuels
- [x] Detour RtlPcToFileHeader
- [x] VEH de diagnostic : code, rip, rsp, pile, nom de l'export le plus proche
- [x] Payload de test CRT et payload brut /NODEFAULTLIB

## A faire (ordre impose)

- [ ] Isoler l'echec : payload brut vs payload CRT sur notepad.exe
- [ ] Corriger la cause du fault a l'entree
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
| 09/11/2026 | Memoire de travail dans `docs/HANDOFF.md` | Survivre aux compressions de conversation |
| 09/11/2026 | Payload brut `/NODEFAULTLIB` comme outil de bisection | Separer un mapper casse d'un CRT non initialise |

## Journal

- 30/10/2026 : scaffold, conventions posees, rien de fonctionnel.
- 30/10/2026 : injecteur ecrit, API ntdll resolue dynamiquement.
- 30/10/2026 : compilation verte. DLL de test + CLI --exe/--pid.
- 30/10/2026 : fix signature hijack_call.
- 09/11/2026 : chemins d'erreur hijack, duree de vie du stub.
- 09/11/2026 : TLS, exceptions, detour RtlPcToFileHeader, VEH diagnostic, payload brut.