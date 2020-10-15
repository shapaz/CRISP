#!/bin/bash

dst=$(mktemp -d)
cp -r * "$dst"
pushd "$dst" >/dev/null

for f in $(find . -type f)
do
	before="Shahar Paz <shaharps \[at\] tau \[dot\] ac \[dot\] il>"
	after="<author anonymized>"
	sed -i -e "s#$before#$after#g" "$f"

	before="<https://github\.com/shapaz/CRISP>"
	after="<link anonymized>"
	sed -i -e "s#$before#$after#g" "$f"

	before="(https://ia\.cr/2020/529)"
	after="(link-anonymized)"
	sed -i -e "s#$before#$after#g" "$f"

	before="https://github\.com/shapaz/CRISP\.git"
	after="<link anonymized>"
	sed -i -e "s#$before#$after#g" "$f"
done

zip -u code.zip $(find . -type f | grep -v "^\\./anonymize.sh\$")
popd > /dev/null
mv "$dst/code.zip" .
rm -rf "$dst"