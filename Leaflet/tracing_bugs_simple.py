import re
import os
import subprocess
from subprocess import Popen, PIPE


if __name__ == '__main__' :
    # On ouvre notre fichier qui nous permettra de tracer les bugs
    with open("tracing_bugs.txt") as file:
        data = file.readlines()
        file.close()

    # On se palce dans le répertoire de travail
    os.chdir('uut')

    # Pour chaque fichier à tracer
    for i in range(len(data)):
        if(data[i].split(' ')[0]=='Fichier'):
            bug_candidat_file = {}
            # Si on a un commit candidat pour le bug concerné
            if('undefined' not in data[i+2].split(' ')[1]):
                # On stocke les commit à visiter et à tracer
                commit_a_tracer = data[i+4].split(' ')[1].split(',')
                commit_a_tracer[len(commit_a_tracer)-1]=re.sub('\n','',commit_a_tracer[len(commit_a_tracer)-1])
                # On stocke le nom du fichier
                fichier = re.sub('\n','',data[i].split(' ')[1])

                #print(commit_a_tracer)
                #try:

                # On exécute notre commande git diff qui va afficher les modification du fichier entre le commit qui fixe le bug (ancien) et le commit candidat au bug (celui dans lequel les bugs seraient apparus pour la première fois)
                result = subprocess.check_output(['git','diff',commit_a_tracer[len(commit_a_tracer)-1],commit_a_tracer[0],'--',fichier],stderr=subprocess.STDOUT)
                
                #except subprocess.CalledProcessError as exc:
                #    print("Status : FAIL", exc.returncode, exc.output)
                #else:
                #    print("Output: \n{}\n".format(result))
                
                # Mise en forme du résultat de la commande précédente
                result = result.decode('utf-8').split('\n')
                # Chaque différence est stocké
                difference = [line.split('@@')[1].strip() for line in result if len(re.findall('@@ .+ @@',line)) > 0]
                
                #print(difference)

                # Si des différences sont présentes
                if(len(difference) > 0) :
                    # On ne garde que l'information qui concerne ce qui a été ajouté
                    difference2 = [e.split(' ')[1] for e in difference]

                    #print(difference2)

                    # On met en forme ce qui a été ajouté. On a donc une liste de listes à 2 éléments [début d'ajout,fin d'ajout]
                    difference3 = [[int(e.split(',')[0]),int(e.split(',')[0])+int(e.split(',')[1])-1] for e in difference2 if len(e.split(',')) > 1]

                    #print(difference3)
                    #print('Commit initial : '+commit_a_tracer[0])
                    #print('Commit actuel : '+commit_a_tracer[len(commit_a_tracer)-1])

                    # Ces différences sont nos candidats bugs (les bugs potentiels)
                    bug_candidat_file[fichier] = [bug for bug in difference3 if bug != [0,-1]]

                    #print(bug_candidat_file)

                    # Si des différences sont présentes
                    if(len(bug_candidat_file[fichier]) != 0) :
                        # On affiche les emplacements des bugs dans le commit initial (celui dans lequel les bugs seraient apparus pour la première fois)
                        print('Fichier '+fichier)
                        print('Commit_responsable '+commit_a_tracer[0])
                        print('Emplacements_des_bugs',bug_candidat_file[fichier])
                        print()