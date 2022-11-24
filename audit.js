// import fetch from "node-fetch";
// import vulnerableJson from "./json/vulnerable.json" assert {type: "json"};
// import packagesListJson from "./json/fulllist.json" assert {type: "json"};
// import outdatedPackages from "./json/outdated.json" assert {type: "json"};
// import { createObjectCsvWriter } from "csv-writer";
const fetch = require("node-fetch");
const vulnerableJson = require("./audit/audit.json");
const packagesListJson = require("./audit/list.json");
const outdatedPackages = require("./audit/outdated.json");
const { createObjectCsvWriter } = require("csv-writer");
const _ = require("lodash");

const csvWriter = createObjectCsvWriter({
    path: "./audit/directDependencies.csv",
    header: [
        { id: "name", title: "Package Name" },
        { id: "installedVersion", title: "Installed Version" },
        { id: "latestVersion", title: "Latest Version" },
        { id: "npmLink", title: "Source" },
        { id: "severity", title: "Severity" },
        { id: "type", title: "Type" },
        { id: "info", title: "Info" },
    ]
});

const csvWriter1 = createObjectCsvWriter({
    path: "./audit/indirectDependencies.csv",
    header: [
        { id: "name", title: "Package Name" },
        { id: "installedVersion", title: "Installed Version" },
        { id: "latestVersion", title: "Latest Version" },
        { id: "npmLink", title: "Source" },
        { id: "severity", title: "Severity" },
        { id: "info", title: "Info" },
    ]
});


const vulnerabilities = vulnerableJson.vulnerabilities || {};
// const vulnerabilitiesMetadata = vulnerableJson.metadata?.vulnerabilities;
const existingDependencies = packagesListJson.dependencies || {};


async function getPackageLatestVersion(packageName = "") {
    if (packageName.trim().length) {
        return new Promise((resolve, reject) => {
            fetch(`https://registry.npmjs.com/-/v1/search?text=${packageName}&size=1`)
                .then(res => res.json())
                .then(data => {
                    resolve(data);
                });
        });
    }
}

async function prepareDirectDependenciesData() {
    const data = [];
    for (const eachPackage in existingDependencies) {
        if ((vulnerabilities[eachPackage]?.isDirect) || Object.keys(outdatedPackages).includes(eachPackage)) {
            let tempData = {};
            tempData["name"] = eachPackage;
            tempData["installedVersion"] = existingDependencies[eachPackage]?.version || getNestedDependencyVersion(eachPackage);
            const packageResponse = await getPackageLatestVersion(eachPackage);
            if (packageResponse.total > 0) {
                const packageDetails = packageResponse.objects[0].package;
                if (packageDetails.name == eachPackage) {
                    tempData["latestVersion"] = packageDetails.version;
                    tempData["npmLink"] = packageDetails.links.npm;
                    tempData["severity"] = vulnerabilities[eachPackage]?.severity || "Not Available";
                    tempData["type"] = Object.keys(vulnerabilities).includes(eachPackage) ? "Deprecated/Vulnerable" : Object.keys(outdatedPackages).includes(eachPackage) ? "Outdated" : "Not Available";
                    let tempTitle = "";
                    (vulnerabilities[eachPackage]?.via || []).forEach(el => {
                        if(typeof el === "object") {
                            tempTitle += `${el.title}\n`
                        }
                    });
                    tempData["info"] = tempTitle.length > 0 ? tempTitle : "-";
                }
            }
            data.push(tempData);
        }
    }
    csvWriter.writeRecords(data)
        .then(() => {
            console.log("DIRECT DEPENDENCIES CSV CREATED.");
        });
}

async function prepareIndirectDependenciesData() {
    const data = [];
    for (const eachPackage in vulnerabilities) {
        if(vulnerabilities[eachPackage]?.isDirect){
            continue;
        }
        let tempData = {};
        tempData["name"] = eachPackage;
        tempData["installedVersion"] = existingDependencies[eachPackage]?.version || getNestedDependencyVersion(eachPackage);
        const packageResponse = await getPackageLatestVersion(eachPackage);
        if (packageResponse.total > 0) {
            const packageDetails = packageResponse.objects[0].package;
            if (packageDetails.name == eachPackage) {
                tempData["latestVersion"] = packageDetails.version;
                tempData["npmLink"] = packageDetails.links.npm;
                tempData["severity"] = vulnerabilities[eachPackage]?.severity || "Not Available";
                let tempTitle = "";
                (vulnerabilities[eachPackage].via || []).forEach(el => {
                    if(typeof el === "object") {
                        tempTitle += `${el.title}\n`
                    }
                });
                tempData["info"] = tempTitle.length > 0 ? tempTitle : "-";
            }
        }
        data.push(tempData);
    }
    csvWriter1.writeRecords(data)
        .then(() => {
            console.log("INDIRECT DEPENDENCIES CSV CREATED.");
        });
}

function getNestedDependencyVersion(packageName = "") {
    let packageVersion = null;
    _.find(existingDependencies, el=>{
        if(el.dependencies){
            if(Object.keys(el.dependencies).includes(packageName)) {
                packageVersion = el.dependencies[packageName].version;
                return true;
            }
        }
    })
    return packageVersion;
}

prepareDirectDependenciesData();
prepareIndirectDependenciesData();
