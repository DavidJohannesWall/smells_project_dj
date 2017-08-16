import re
import os
import subprocess
import json


if __name__ == '__main__' :
    # On ouvre notre fichier qui contient les emplacements des vulnérabilités
    with open("emplacements_vulnerabilites.txt") as file:
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
            # On stocke le commit vulnérable
            commit = data[i+1].split(' ')[1].split('\n')[0]
            # On stocke les emplacements de vulnérabilités du fichier dans le commit
            vuln = eval(re.sub('\n','',re.sub('Emplacements_des_vulnerabilites ','',data[i+2])))
            
            # On se place dans le commit vulnérable
            os.system('git reset -q --hard && git checkout -q '+commit)

            # On applique le parsage sur le fichier vulnérable pour élargir les emplacements potentiels des vulnérabilités
            subprocess.run(['node','../ast.js',file])

            # On ouvre le fichier de parsage généré précédemment
            with open("ast.json") as json_data:
                ast = json.load(json_data)
                json_data.close()

            # On affiche les variables et fonctions créées, avec leur initialisation et leurs appels
            # print(ast)

            new_vulnerabilities = []

            # On traite les intersections entre les vulnérabilités actuelles que nous connaissons et les initialisations/appels de variables et fonctions
            # Pour chacune des vulnérabilités actuelles connues
            for v in vuln:
                # Pour chaque variable et fonction connue
                for elements in ast.keys():
                    if(ast[elements] != {}):
                        for element in ast[elements].keys():
                            # Si l'intersection entre la vulnérabilité et l'initialisation de la variable/fonction est non vide
                            inter = [max(v[0], ast[elements][element]['Orig'][0]),min(v[-1], ast[elements][element]['Orig'][-1])] if max(v[0], ast[elements][element]['Orig'][0]) <= min(v[-1], ast[elements][element]['Orig'][-1]) else []
                            if inter != []:
                                # On considère le bloc d'initialisation de la variable/fonction dans les vulnérabilités
                                new_vulnerabilities.append([ast[elements][element]['Orig'][0],ast[elements][element]['Orig'][1]])
                                # On considère tous les endroits d'appel de la fonction/variable dans les vulnérabilités
                                for ref in ast[elements][element]['References']:
                                    new_vulnerabilities.append(ref)
                            # Pour chaque endroit où la fonction/variable est appelée
                            for ref in ast[elements][element]['References']:
                                # Si l'intersection entre la vulnérabilité et l'appel de la fonction/variable est non vide
                                inter = [max(v[0], ref[0]),min(v[-1], ref[-1])] if max(v[0], ref[0]) <= min(v[-1], ref[-1]) else []
                                if inter != []:
                                    # On considère le bloc d'initialisation de la variable/fonction dans les vulnérabilités
                                    new_vulnerabilities.append([ast[elements][element]['Orig'][0],ast[elements][element]['Orig'][1]])
                                    # On considère tous les endroits d'appel de la fonction/variable dans les vulnérabilités
                                    for ref2 in ast[elements][element]['References']:
                                        new_vulnerabilities.append(ref2)
            
            # On ajoute nos nouvelles vulnérabilités à celles déjà connues
            vuln = vuln + new_vulnerabilities

            # On affiche le nom du fichier, le commit vulnérable, ainsi que les endroits potentiels de vulnérabilités
            print('Fichier '+file)
            print('Commit_responsable '+commit)
            print('Emplacements_des_vulnerabilites',vuln)
            print()

            # On supprime le fichier ast.json
            subprocess.run(['rm','-f','ast.json'])
            print()