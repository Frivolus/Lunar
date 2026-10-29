# ETAT DU PROJET

> **Lu par l'agent AVANT toute modification. Mis a jour APRES chaque tache.**
> Ne jamais reecrire un fichier existant depuis zero : patcher, completer, ou demander.

## Position

- Phase : 0 — fondations
- Derniere action : injecteur ecrit (process, hijack, manual map, unlink PEB)
- Prochaine action : corriger les erreurs de compilation injecteur

## Fait

- [x] Repo prive cree
- [x] Arborescence src/ injector / hyperion / core / launcher
- [x] CMake racine + sous-projets vides
- [x] .gitignore Visual Studio + CMake

## A faire (ordre impose)

- [x] `src/injector` ecrit, non compile
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

## Journal

- 30/10/2026 : scaffold, conventions posees, rien de fonctionnel.
- 30/10/2026 : injecteur ecrit, API ntdll resolue dynamiquement. Manque : TLS callbacks, unlink arbre LdrpModuleIndexBase, syscalls indirects.

