import re
import os
import subprocess
import json


if __name__ == '__main__' :
    # On ouvre notre fichier qui contient les emplacements des bugs
    with open("emplacements_bugs.txt") as file:
        data = file.readlines()
        file.close()

    # On se palce dans le répertoire de travail
    os.chdir('uut')

    # Pour chaque fichier
    for i in range(len(data)):
        if(data[i].split(' ')[0]=='Fichier'):
            # On stocke le nom du fichier
            file = data[i].split(' ')[1].split('\n')[0]
            #print(file)
            # On stocke le commit "buggé"
            commit = data[i+1].split(' ')[1].split('\n')[0]
            # On stocke les emplacements de bugs du fichier dans le commit
            bugs = eval(re.sub('\n','',re.sub('Emplacements_des_bugs ','',data[i+2])))
            
            # On se place dans le commit "buggé"
            os.system('git reset -q --hard && git checkout -q '+commit)

            # On applique le parsage sur le fichier "buggé" pour élargir les emplacements potentiels de bugs
            subprocess.run(['node','../ast.js',file])

            # On ouvre le fichier de parsage généré précédemment
            with open("ast.json") as json_data:
                ast = json.load(json_data)
                json_data.close()

            # On affiche les variables et fonctions créées, avec leur initialisation et leurs appels
            # print(ast)

            new_bugs = []

            # On traite les intersections entre les bugs actuels que nous connaissons et les initialisations/appels de variables et fonctions
            # Pour chacun des bugs actuels connus
            for bug in bugs:
                # Pour chaque variable et fonction connue
                for elements in ast.keys():
                    if(ast[elements] != {}):
                        for element in ast[elements].keys():
                            # Si l'intersection entre le bug et l'initialisation de la variable/fonction est non vide
                            inter = [max(bug[0], ast[elements][element]['Orig'][0]),min(bug[-1], ast[elements][element]['Orig'][-1])] if max(bug[0], ast[elements][element]['Orig'][0]) <= min(bug[-1], ast[elements][element]['Orig'][-1]) else []
                            if inter != []:
                                # On considère le bloc d'initialisation de la variable/fonction dans les bugs
                                new_bugs.append([ast[elements][element]['Orig'][0],ast[elements][element]['Orig'][1]])
                                # On considère tous les endroits d'appel de la fonction/variable dans les bugs
                                for ref in ast[elements][element]['References']:
                                    new_bugs.append(ref)
                            # Pour chaque endroit où la fonction/variable est appelée
                            for ref in ast[elements][element]['References']:
                                # Si l'intersection entre le bug et l'appel de la fonction/variable est non vide
                                inter = [max(bug[0], ref[0]),min(bug[-1], ref[-1])] if max(bug[0], ref[0]) <= min(bug[-1], ref[-1]) else []
                                if inter != []:
                                    # On considère le bloc d'initialisation de la variable/fonction dans les bugs
                                    new_bugs.append([ast[elements][element]['Orig'][0],ast[elements][element]['Orig'][1]])
                                    # On considère tous les endroits d'appel de la fonction/variable dans les bugs
                                    for ref2 in ast[elements][element]['References']:
                                        new_bugs.append(ref2)
            
            # On ajoute nos nouveaux bugs à ceux déjà connus
            bugs = bugs + new_bugs

            # On affiche le nom du fichier, le commit "buggé", ainsi que les endroits potentiels de bugs
            print('Fichier '+file)
            print('Commit_responsable '+commit)
            print('Emplacements_des_bugs',bugs)
            print()

            # On supprime le fichier ast.json
            subprocess.run(['rm','-f','ast.json'])
            print()