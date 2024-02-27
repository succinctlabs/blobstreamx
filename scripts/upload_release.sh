# Read release id from parameters
RELEASE_ID=$1
OUTPUT_FOLDER=$2

# Load .env
source .env

# Print out R2_ENDPOINT, RELEASE_ID, OUTPUT_FOLDER
echo "R2_ENDPOINT: ${R2_ENDPOINT}"
echo "RELEASE_ID: ${RELEASE_ID}"
echo "OUTPUT_FOLDER: ${OUTPUT_FOLDER}"

mkdir -p ./${OUTPUT_FOLDER}

# Copy the release from R2 to local
AWS_PROFILE=r2 aws s3 cp -r --endpoint-url ${R2_ENDPOINT} s3://platform-artifacts/main/releases/${RELEASE_ID} ./${OUTPUT_FOLDER}

# tar the release folder
tar -czvf ${RELEASE_ID}.tar.gz ${OUTPUT_FOLDER}

# Upload the tar to s3
AWS_PROFILE=default aws s3 cp ${RELEASE_ID}.tar.gz s3://public-blobstreamx-circuits/${RELEASE_ID}.tar.gz --endpoint-url ${S3_ENDPOINT}

# TODO: Clean up the tar file