# Regles agent

1. Lire `docs/HANDOFF.md` en entier avant toute action et apres chaque compression de conversation.
2. Lire `docs/STATE.md` en entier avant toute modification.
3. L'utilisateur n'execute que du PowerShell : l'agent ecrit le code, fournit les commandes, interprete les erreurs.
4. Ne pas regenerer un fichier existant : appliquer un patch cible.
5. Mettre a jour `docs/STATE.md` et `docs/HANDOFF.md` apres chaque tache.
6. Respecter les conventions figees. Toute deviation se discute avant.
7. Ne pas toucher aux fichiers hors du perimetre demande.
8. Aucun offset en dur hors de `src/core/offsets/`.