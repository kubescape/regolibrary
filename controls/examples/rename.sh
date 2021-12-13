for f in *.txt; do 
    mv -- "$f" "${f%.txt}.yaml"
done