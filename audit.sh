package='csv-writer'
installed_csv_writer=0
if [ `npm list | grep -c $package` -eq 0 ]; then
    echo "installing $package"
    installed_csv_writer=1
    npm i -D $package
fi

rm -rf ./directDependencies.csv && rm -rf ./indirectDependencies.csv && rm -rf audit && mkdir audit
npm list --depth=1 --json > audit/list.json
npm audit --json > audit/audit.json
npm outdated --json > audit/outdated.json
node audit.js

if [ $installed_csv_writer -eq 1 ]; then
    echo "uninstalling $package"
    npm uninstall $package
fi