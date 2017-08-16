import re
import json
import os
import subprocess
from subprocess import Popen, PIPE

# On ouvre le fichier qui contient les vulnérabilités pour chaque commit
with open("vulnerabilities.txt") as file:
    data = file.readlines()
    file.close()

# On met en forme les données
for i in range(len(data)):
    data[i] = data[i].split('\n')[0]

# result contiendra une forme dictionnaire synthétique de la première apparition de chaque vulnérabilité
result = []

# Pour chaque époque
for i in range(len(data)):
    if (data[i].split(' : ')[0] == "Epoque"):
        r = {}
        # On enregistre l'époque
        r["epoque"] = eval(data[i].split(' : ')[1])
        # On enregistre le commit
        r["commit"] = data[i+1].split(' : ')[1]
        # On enregistre le nombre de vulnérabilités
        r["nb_vulnerabilities"] = eval(data[i+2].split(' : ')[1])
        # Si le nombre de vulnérabilités est plus grand que 0
        if r["nb_vulnerabilities"] > 0 :
            r["vulnerabilities"] = []
            # Pour chaque vulnérabilité du commit
            for j in range(r["nb_vulnerabilities"]):
                v = {}
                # On enregistre les diverses informations de la vulnérabilité (titre, module vulnérable, introduction...)
                v["title"] = data[i+4*(j+1)].split(' : ')[1]
                v["vulnerable_module"] = data[i+4*(j+1)+1].split(' : ')[1]
                v["introducing_through"] = [module.split('@')[0] for module in data[i+4*(j+1)+2].split(' : ')[1].split(' and ')]
                # On stocke ces infomations
                r["vulnerabilities"].append(v)
            # On stocke les données de vulnérabilité concernant ce commit
            result.append(r)

# On veut savoir ici les vulnérabilités uniques qui apparaissent pour la première fois
unique_vulnerabilities = []
# Pour chaque élément de result (donc chaque commit)
for i in range(len(result)):
    # Pour chaque vulnérabilité du commit
    for j in range(len(result[i]["vulnerabilities"])):
        found = False
        # Pour chaque vulnérabilité unique enregistrée dans unique_vulnerabilities
        for k in range(len(unique_vulnerabilities)):
            # Si la vulnérabilité actuelle du commit traité a déjà été enregistrée
            if(unique_vulnerabilities[k]["title"] == result[i]["vulnerabilities"][j]["title"] and unique_vulnerabilities[k]["vulnerable_module"] == result[i]["vulnerabilities"][j]["vulnerable_module"] and set(unique_vulnerabilities[k]["introducing_through"]) == set(result[i]["vulnerabilities"][j]["introducing_through"])):
                # Alors on indique qu'elle a déjà été enregistrée
                found = True
        # Si la vulnérabilité n'a pas encore été enregistrée
        if found == False:
            # On ajoute ses informations (époque, commit, titre, module vulnérable, introduction...) dans unique_vulnerabilities
            unique_vulnerabilities.append({"epoque" : result[i]["epoque"], "commit" : result[i]["commit"], "title" : result[i]["vulnerabilities"][j]["title"], "vulnerable_module" : result[i]["vulnerabilities"][j]["vulnerable_module"], "introducing_through" : result[i]["vulnerabilities"][j]["introducing_through"]})

# On ne retient que les commits qui expérimentent la première apparition d'une vulnérabilité
vulnerable_commits = list(set([element["commit"] for element in unique_vulnerabilities]))

# On va modifier le fichier set_smelly pour indiquer quels commits expérimentent l'apparition d'une vulnérabilité
with open("set_smelly.json") as json_data:
    set_smelly = json.load(json_data)
    json_data.close()

# Pour chaque commit du projet
for i in range(len(set_smelly)) :
    # Pour chaque commit qui expérimente l'introduction d'une vulnérabilité
    for commit in vulnerable_commits :
        # Si on a correspondance entre les commits
        if set_smelly[i]["commit"] == commit :
            # Alors on indique que le commit est vulnérable dans set_smelly
            set_smelly[i]["vulnerable"] = 1
# Pour tous les commits du projets qui n'ont pas été marqués comme vulnérables, on indique qu'ils ne le sont pas
for i in range(len(set_smelly)) :
    if "vulnerable" not in set_smelly[i].keys():
        set_smelly[i]["vulnerable"] = 0

# On enregistre nos nouvelles données, qui établissent si les commits sont vulnerables ou non
with open('set_smelly2.json','w') as outfile:
    json.dump(set_smelly,outfile)

# On ovure le fichier qui contient l'historique des fichiers du projet
with open("historique_fichiers2.json") as json_data:
    historique = json.load(json_data)
    json_data.close()

# On veut ici regarder les fichiers à "git diff", entre le commit sain (dernier commit entre le commit vulnérable dans lequel le fichier est modifié) et le commit vulnérable
commits_to_git_diff = []
# Pour chaque fichier du projet
for file in historique.keys():
    # Si le fichier se finit pas .js et pas par .min.js
    if(file.endswith(".js") == True and file.endswith(".min.js") == False) :
        # Pour chaque commit vulnérable
        for commit in vulnerable_commits:
            # Si le commit se trouve dans l'historique des commits du fichier
            if commit in historique[file]:
                # Alors on enregistre le commit précédent dans lequel le fihcier a été modifié (ainsi que le commit vulnérable)
                pos = historique[file].index(commit)-1
                commits_to_git_diff.append([file,historique[file][pos],commit])

#print(commits_to_git_diff)

# Ici, on va faire un git diff pour identifier plus précisément les vulnérabilités des fichiers, en localisant ces possibles vulnérabilités
# On se place dans le répertoire du projet
os.chdir('uut')
vulnerability_candidat_file = {}
# Pour chaque élément à "git diff"
for element in commits_to_git_diff:
    # On exécute notre commande git diff qui va afficher les modification du fichier entre le commit sain (ancien) et le commit vulnérable
    result = subprocess.check_output(['git','diff',element[1],element[2],'--',element[0]],stderr=subprocess.STDOUT)

    # Mise en forme du résultat de la commande précédente
    result = result.decode('utf-8').split('\n')
    # Chaque différence est stockée
    difference = [line.split('@@')[1].strip() for line in result if len(re.findall('@@ .+ @@',line)) > 0]

    # Si des différences sont présentes
    if(len(difference) > 0) :
        # On ne garde que l'information qui concerne ce qui a été ajouté
        difference2 = [e.split(' ')[1] for e in difference]

        # On met en forme ce qui a été ajouté. On a donc une liste de listes à 2 éléments [début d'ajout,fin d'ajout]
        difference3 = [[int(e.split(',')[0]),int(e.split(',')[0])+int(e.split(',')[1])-1] for e in difference2 if len(e.split(',')) > 1]

        # Ces différences sont nos candidats (emplacements possibles des vulnérabilités)
        vulnerability_candidat_file[element[0]] = [v for v in difference3 if v != [0,-1]]

        # Si des différences sont présentes
        if(len(vulnerability_candidat_file[element[0]]) != 0) :
            # On affiche les emplacements des vulnérabilités dans les fichiers du commit vulnérable
            print('Fichier '+element[0])
            print('Commit_responsable '+element[2])
            print('Emplacements_des_vulnerabilites',vulnerability_candidat_file[element[0]])
            print()