#!/bin/bash
echo "Installation des dépendances Node..."
cd frontend
npm install --legacy-peer-deps
npm run build
cd ..
echo "Build React terminé !"
