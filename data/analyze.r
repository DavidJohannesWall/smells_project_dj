library(survival)
library(rms)

mydata <- read.csv("/Users/amir/Projects/jsmell/data3.csv")
attach(mydata)
x <- cbind(prevBugs, smelly)

kmsurvival <- npsurv(Surv(time, event) ~ smelly)
# summary(kmsurvival)
jpeg('rplot.jpg')
survplot(kmsurvival, xlab = "Time", ylab = "Survival Probability")
dev.off()