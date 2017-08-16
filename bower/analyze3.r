library(survival)
library(rms)

variables <- c('linesAdded','linesRemoved','totalChurn','loc','maxstatements','maxdepth','complexity','maxlen','maxparams','maxnestedcallbacks','complexswitchcase','thisassign','complexchaining','noreassign','noextrabind','condassign','smelly')

type_smells <- c('maxstatements','maxdepth','complexity','maxlen','maxparams','maxnestedcallbacks','complexswitchcase','thisassign','complexchaining','noreassign','noextrabind','condassign')

mydata <- read.csv("Bower_vulnerabilities_smells_file-grain.csv")
attach(mydata)
write(sprintf("Results of vulnerabilities-smells with file grain"),"Bower_vulnerabilities-smells_summary.txt")

for (var in variables) {
	if (var == 'smelly') {
		kmsurvival <- npsurv(Surv(time, event) ~ get(var))
		jpeg('Bower_vulnerabilities_smells_file-grain_rplot.jpg')
		plot(kmsurvival,xlab = "Time (in hours)", ylab = "Survival Probability",lty = c(1,3),xaxs="r")
		legend("bottomleft", legend=c("NotSmelly", "Smelly"),lty=c(1,3),cex=1.3)
		dev.off()
	}
	write(sprintf("		Covariate : %s",var),"Bower_vulnerabilities-smells_summary.txt",append=TRUE)
	coxsurvival <- coxph(Surv(time, event) ~ get(var))
	write(sprintf("			exp(coef) : %g",coef(summary(coxsurvival))[2]),"Bower_vulnerabilities-smells_summary.txt",append=TRUE)
	write(sprintf("			p-value (Cox hazard model) : %g",coef(summary(coxsurvival))[5]),"Bower_vulnerabilities-smells_summary.txt",append=TRUE)
	coxsurvival <- coxph(Surv(time, event) ~ get(var))
	testdata <- cox.zph(coxsurvival)
	write(sprintf("			p-value (Porportional hazards assumption) : %g",testdata[[1]][3]),"Bower_vulnerabilities-smells_summary.txt",append=TRUE)
}

detach(mydata)
mydata <- read.csv("Bower_vulnerabilities_smells_line-grain.csv")
attach(mydata)
write(sprintf("Results of vulnerabilities-smells with line grain"),"Bower_vulnerabilities-smells_summary.txt",append = TRUE)

for (var in variables) {
	if (var == 'smelly') {
		kmsurvival <- npsurv(Surv(time, event) ~ get(var))
		jpeg('Bower_vulnerabilities_smells_line-grain_rplot.jpg')
		plot(kmsurvival,xlab = "Time (in hours)", ylab = "Survival Probability",lty = c(1,3),xaxs="r")
		legend("bottomleft", legend=c("NotSmelly", "Smelly"),lty=c(1,3),cex=1.3)
		dev.off()
		ev <- "event"
	}
	write(sprintf("		Covariate : %s",var),"Bower_vulnerabilities-smells_summary.txt",append=TRUE)
	if (is.element(var,type_smells) == TRUE) {
		ev <- paste("event",var,sep='')
	}
	else {
		ev <- "event"
	}
	coxsurvival <- coxph(Surv(time, get(ev)) ~ get(var))
	write(sprintf("			exp(coef) : %g",coef(summary(coxsurvival))[2]),"Bower_vulnerabilities-smells_summary.txt",append=TRUE)
	write(sprintf("			p-value (Cox hazard model) : %g",coef(summary(coxsurvival))[5]),"Bower_vulnerabilities-smells_summary.txt",append=TRUE)
	coxsurvival <- coxph(Surv(time, get(ev)) ~ get(var))
	testdata <- cox.zph(coxsurvival)
	write(sprintf("			p-value (Porportional hazards assumption) : %g",testdata[[1]][3]),"Bower_vulnerabilities-smells_summary.txt",append=TRUE)
}

detach(mydata)
mydata <- read.csv("Bower_vulnerabilities_smells_line-grain_large.csv")
attach(mydata)
write(sprintf("Results of vulnerabilities-smells with line grain and considering dependencies"),"Bower_vulnerabilities-smells_summary.txt",append = TRUE)

for (var in variables) {
	if (var == 'smelly') {
		kmsurvival <- npsurv(Surv(time, event) ~ get(var))
		jpeg('Bower_vulnerabilities_smells_line-grain_large_rplot.jpg')
		plot(kmsurvival,xlab = "Time (in hours)", ylab = "Survival Probability",lty = c(1,3),xaxs="r")
		legend("bottomleft", legend=c("NotSmelly", "Smelly"),lty=c(1,3),cex=1.3)
		dev.off()
		ev <- "event"
	}
	write(sprintf("		Covariate : %s",var),"Bower_vulnerabilities-smells_summary.txt",append=TRUE)
	if (is.element(var,type_smells) == TRUE) {
		ev <- paste("event",var,sep='')
	}
	else {
		ev <- "event"
	}
	coxsurvival <- coxph(Surv(time, get(ev)) ~ get(var))
	write(sprintf("			exp(coef) : %g",coef(summary(coxsurvival))[2]),"Bower_vulnerabilities-smells_summary.txt",append=TRUE)
	write(sprintf("			p-value (Cox hazard model) : %g",coef(summary(coxsurvival))[5]),"Bower_vulnerabilities-smells_summary.txt",append=TRUE)
	coxsurvival <- coxph(Surv(time, get(ev)) ~ get(var))
	testdata <- cox.zph(coxsurvival)
	write(sprintf("			p-value (Porportional hazards assumption) : %g",testdata[[1]][3]),"Bower_vulnerabilities-smells_summary.txt",append=TRUE)
}
