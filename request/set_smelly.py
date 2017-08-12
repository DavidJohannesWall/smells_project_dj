import json
from pprint import pprint
import re
from collections import Counter
import heapq
import math

# Ouverture du fichier data.json
with open("data.json") as json_data:
    data = json.load(json_data)
    json_data.close()

# On définit les noms des types de smell
smells = ['max-statements','max-depth','complexity','max-len','max-params','max-nested-callbacks','complex-switch-case','complex-chaining']
smells_boolean = ['no-reassign','no-extra-bind','cond-assign','this-assign']
smells_values = {}
smells_seuil = {}

# Pour chaque type de smell, on va stocker les valeurs (poids) pour chacun des fichiers de data.json
for smell in smells:
    smells_values[smell] = []

# Pour chaque type de smell (autres que les smells booléens)
for type_smell in smells:
    # Pour chaque commit
    for commit in data:
        # Pour chaque changement effectué
        for change in commit['changes']:
            smell = change['smells']
            # Si le type de smell est présent dans le fichier changé
            if(type_smell in smell.keys()):
                # On ajoute le max des poids, si on a plusieurs fois le même type de code smell (le smell le plus important caractérise le fichier)
                smells_values[type_smell].append(max([e[0] for e in smell[type_smell]]))

# Pour chacun des types de smell, on va définir un seuil à partir des valeurs récupérées précédemment. Au delà de ce seuil, le smell sera considéré comme véritable. En dessous, il ne sera psa pris en compte.
# Le seuil choisi ici est 10% (donc les 10% smell les plus "gros" sont considérés comme véritables)
for smell in smells_values.keys():
    #if(math.floor(0.25*len(smells_values[smell])) == 0):
    if(math.floor(0.1*len(smells_values[smell])) == 0):
        smells_seuil[smell] = max(smells_values[smell]) if len(smells_values[smell]) > 0 else 0
    else:
        #smells_seuil[smell] = round((min(heapq.nlargest(round(0.25*len(smells_values[smell])),smells_values[smell]))+10*max(smells_values[smell]))/11)
        smells_seuil[smell] = min(heapq.nlargest(math.floor(0.1*len(smells_values[smell])),smells_values[smell]))
for smell in smells_boolean:
    smells_seuil[smell] = 1

# Pour chaque type de smell
for type_smell in smells:
    # Pour chaque commit
    for i in range(len(data)):
        # Pour chaque changement
        for j in range(len(data[i]['changes'])):
            # Si le type de smell est dans le fichier modifié
            if(type_smell in data[i]['changes'][j]['smells'].keys()): 
                # Si un des smell a un poids supérieur au seuil établi précédemment
                if(max([e[0] for e in data[i]['changes'][j]['smells'][type_smell]])>=smells_seuil[type_smell]):
                    # On ne garde que les smells dont le poids est égal au max des poids des smells (les smells les plus caractéristiques)
                    data[i]['changes'][j]['smells'][type_smell] = [e for e in data[i]['changes'][j]['smells'][type_smell] if e[0] == max([e[0] for e in data[i]['changes'][j]['smells'][type_smell]])]
                else:
                    # Sinon, on supprime ce type de smell des données du fichier modifié
                    del data[i]['changes'][j]['smells'][type_smell]

# Pour chaque commit
for i in range(len(data)):
    # Pour chaque changement (donc chaque fichier modifié)
    for j in range(len(data[i]['changes'])):
        # Si ce changement inclut des smells 
        if(len(data[i]['changes'][j]['smells']) > 0): 
            # Alors on marque ce fichier comme étant smelly
            data[i]['changes'][j]['smelly'] = 1
        else:
            # Sinon le fichier est marqué comme non smelly
            data[i]['changes'][j]['smelly'] = 0

#print(smells_seuil)
#print(smells_values)
#print(data[10])

# On enregistre nos nouvelles données, qui établissent si les fichiers sont smelly ou non
with open('set_smelly.json','w') as outfile:
    json.dump(data,outfile)

with open('seuil_poids_smells.json','w') as outfile2:
    json.dump(smells_seuil,outfile2)
