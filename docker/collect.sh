truncate -s 0 ./images.txt
for i in {1..10}
do
echo $i
echo "https://hub.docker.com/api/content/v1/products/search?image_filter=official&page=$i&page_size=100&q=&type=image" 
curl -k "https://hub.docker.com/api/content/v1/products/search?image_filter=official&page=$i&page_size=100&q=&type=image" -H 'Accept: application/json' -H 'Content-Type: application/json'|jq -r '.summaries[].slug' >> ./images.txt
done

