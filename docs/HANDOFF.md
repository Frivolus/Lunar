# HANDOFF — memoire de travail agent

> Lu en entier AVANT toute action et apres chaque compression de conversation.
> Ne jamais reecrire ce fichier depuis zero : completer Journal et Prochaine action.

## Protocole de travail

- L'utilisateur ne fait qu'une chose : executer les commandes PowerShell fournies et coller les sorties, erreurs comprises.
- L'agent fournit les commandes, ecrit le code, interprete les erreurs, corrige. L'utilisateur ne code pas et ne choisit pas l'ordre des briques.
- Un bloc de commande = une etape. Pas d'enchainement de briques dans un meme bloc.
- Toujours se placer a la racine du repo en debut de bloc et verifier la presence de `.git`.
- Jamais de fichier ecrit a la main par l'utilisateur : tout passe par here-string PowerShell, encodage UTF-8 avec BOM.
- En cas d'erreur : lire la sortie complete, corriger, redonner un bloc. Ne jamais dire "reessaie".
- Ne jamais demander de confirmation pour une brique deja planifiee ici.

## Etat technique

- Depot : Frivolus/Lunar (prive). Branche main. Chemin local : C:\dev\Lunar.
- Phase 0, fondations. Seul `src/injector` est ecrit et compile.
- Cible : injecteur manual map pour RobloxPlayerBeta.exe, sans CreateRemoteThread, sans driver noyau.
- Objectif produit : executor Luau (Hyperion emulation + moteur sUNC), launcher UI.

### Fait

- Arborescence complete, CMake racine, sous-projets.
- `src/injector` complet et compilant : ntdll dynamique, Nt* only, hijack de thread + stub NtContinue, unlink Ldr Load/Mem/Init, remap API-set, relocations, wipe headers optionnel, CLI `--exe/--pid/--wipe`.
- DLL de test `tests/payload`.

### Casse / a corriger (bloquant pour le test bout en bout)

1. Aucune DLL payload reelle : `lunar_core` et `lunar_hyperion` sont STATIC, rien ne les lie en SHARED. Les deux `dllmain.cpp` sont le meme blob.
2. `thread_hijack.cpp` : les `return` d'erreur apres `GetThreadContext` laissent le thread cible suspendu avec RIP dans un stub qui va etre libere. `flag`, `slot` et `context` fuient.
3. Le stub est libere par `~Hijack` alors que le thread peut encore y executer `call rax` (`done` est pose avant `NtContinue`).
4. `apply_imports` ne borne pas `u1.AddressOfData` a `image_size`.
5. Pas de callbacks TLS, pas d'unlink de `LdrpModuleIndexBase`, pas de syscalls indirects.

### Prochaine action

Brique 1 : patch `thread_hijack.cpp` (chemins d'erreur, duree de vie du stub, liberation de `context`).

### Ordre impose ensuite

2. `apply_imports` bornage + target `lunar_payload` SHARED, fusion des `dllmain`.
3. Compilation, test `notepad.exe`, verification de `%TEMP%\lunar_payload_ok.txt`.
4. `src/hyperion` : snapshot pages, hook VirtualProtect, anti-debug.
5. `src/core` : VM Luau, ScriptContext, identity 7.
6. `src/core/api` : 86 fonctions sUNC.
7. `tools/dumper` : signature scan.
8. `src/launcher` : UI.

## Conventions figees

- C++20, x64, MSVC, CMake. Aucune dependance externe non validee.
- `snake_case` fonctions, `PascalCase` types, `k_` constantes.
- Pas de `CreateRemoteThread`. Pas de driver noyau.
- Aucun offset en dur hors de `src/core/offsets/`.
- Un commit = une brique. Messages `type: portee - description`.
- Patcher, jamais regenerer un fichier existant.
- Ne pas toucher aux fichiers hors perimetre.

## Decisions

| Date | Decision | Raison |
|---|---|---|
| 30/10/2026 | Repo prive, nom `Lunar` | Pas de fuite, marque courte |
| 30/10/2026 | Payload en 3 binaires (emulator / executor / data) | Patch offsets sans recompiler le signe |
| 30/10/2026 | Injection avant init hyperviseur | Restaurer les hashes apres coup est trop tardif |
| 09/11/2026 | Memoire de travail dans `docs/HANDOFF.md` | Survivre aux compressions de conversation |

## Journal

- 30/10/2026 : scaffold, conventions, rien de fonctionnel.
- 30/10/2026 : injecteur ecrit, API ntdll dynamique.
- 30/10/2026 : compilation verte, DLL de test, CLI multi-cible.
- 30/10/2026 : fix signature hijack_call.
- 09/11/2026 : audit complet de l'injecteur, 5 bloquants releves, mise en place du protocole de passation.
## Mise a jour 09/11/2026

- Brique 1 (patch hijack) : faite, compilation verte, commit e6f2d8c.
- WIP de debug d'une session precedente retrouve non commite : TLS, table d'exceptions, detour RtlPcToFileHeader, VEH diagnostic, payload brut /NODEFAULTLIB, chargement d'import par chemin. Commite tel quel.
- Echec observe : `DllMain n'a pas rendu la main`. Le VEH de diagnostic est en place pour capturer code/rip/rsp/pile.
- Prochain test : payload brut dans notepad.exe. Si le brut passe et le CRT non, c'est l'initialisation CRT. Si les deux echouent, c'est le mapper.
- Les payloads de test ecrivent desormais en dur : `C:\dev\lunar_payload_ok.txt` et `%TEMP%\lunar_raw_ok.txt`.

## Mise a jour 09/11/2026 (2)

- Cause du timeout trouvee : le thread hijacke etait bloque dans un wait noyau (thread principal de cmd.exe en attente clavier). Le RIP injecte ne prend effet qu'au retour en mode utilisateur, jamais atteint.
- Preuve : selftest sur cible a thread actif (`lunar_spin`) -> succes, valeur correcte.
- Injection complete du payload brut sur `lunar_spin` : mappe, DllMain execute, marqueur ecrit, unlink PEB, cible vivante.
- Le mapper, le stub, NtContinue, les imports et les exceptions fonctionnent.
- Reste : payload CRT, puis selection de thread robuste (ignorer les threads bloques).
