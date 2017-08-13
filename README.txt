// Path à exporter pour l’utilisation de nodejs
NODE_PATH="/usr/local/lib/node_modules"
export NODE_PATH

// Setup pour les projets
python3 setup.py

// Traçage des smells des projets
python3 survival_smells.py

// Analyses de survie entre les smells et les bugs
python3 smells_bugs_analyses.py