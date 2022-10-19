#!/bin/bash
GCP_PROJECT=$1
DEPRECATEONDAYS=33
DELETEONDAYS=64
DEBUG=false  # true/false - If set to true then the altering gcloud commands will be skipped.

# https://cloud.google.com/sdk/gcloud/reference/compute/images/deprecate
# Note: Deprecate and Obsolete dates are for visual use only and does not affect the availability or use of an image.
#       Setting the image status of:
#           DEPRECATED - will produce a warning that an image is being deprecated; and if a replacement image is set will suggest the user update to that image.
#           DELETED or OBSOLETE - will produce an error if a new resource is created; but will not delete an image; and if a replacement image is set will suggest the user update to that image.

####
# date calculations have been problematic; easy route was chosen and deprecated/obsolete logic do not use the timestamp in their respective fields; instead the logic looks for the timeframe from creationTimestamp
# ultimately IF the scripts are ran immediatly after an image is created then nobody will see discrepencies; BUT it is possible if the script failed or did not execute and this script was ran on a later day. 
####

# To aid in debugging and validating various commands Docker Desktop was used to help speed up the testing and debugging process.
# Sample command used to get a local container running; and also mounting my base development directory.  Mounting the base directory allowed
# me to edit in my primary editor and then immediately execute and test the updates.
# docker run --entrypoint "/bin/sh" -it -v /Users/jlynch/CloudRepos/gcp_lz/golden-vm-image-configuration:/golden-vm-image-configuration google/cloud-sdk:315.0.0


## TODO: implement ability to target selected image family.  (specific family comma seperated, or all from jenkins parameter)

# Fetch all Image Families that our Packer configuration is supporting
grep "image_family.*= " -h *.pkr.hcl | sed -n -e "s/.*  image_family.*= //p" > supportedImageFamilies.txt
#grep "image_family = " -h windows-2016.pkr.hcl | sed -n -e "s/.*  image_family = //p" > supportedImageFamilies.txt

while read currImageFamily; do
    # Strip the double quotes from currImageFamily variable
    currImageFamily=$(sed -e 's/^"//' -e 's/"$//' <<<"$currImageFamily")
    echo "--------------------------------------------------------------------"
    printf "Evaluating images in the [ %s ] image family.\n" "${currImageFamily}"
    # Get the latest image in the family to be used as the suggested replacement image.
    latestImages=$(gcloud compute images list \
        --project $GCP_PROJECT \
        --filter="name~-golden AND family~$currImageFamily" \
        --limit=1 \
        --sort-by="~creationTimestamp" \
        --format="csv[no-heading](name, selfLink.scope(compute))")
    IFS=',' read -r -a latestImage<<< "$latestImages"
    replacementImageName="${latestImage[0]}"
    replacementImage="https://www.googleapis.com/compute/${latestImage[1]}"
    if [ -z ${replacementImageName} ] ; then
        # if the 'latest' image doesn't exist that means we do not have golden images for this family.
        printf "    No images found for family\n"
    else
        printf "  Latest image name: %s\n" $replacementImageName
        printf "  Latest image link: %s\n\n" $replacementImage
        # Get active images; and set obsolete and delete dates if they are missing.
        for activeImages in $(gcloud compute images list \
            --project $GCP_PROJECT \
            --filter="name~-golden AND family~$currImageFamily" \
            --sort-by="~creationTimestamp" \
            --format="csv[no-heading](name, creationTimestamp.date('%Y-%m-%d'))")
        do
            IFS=',' read -r -a activeImage<<< "$activeImages"
            NAME="${activeImage[0]}"
            if [ -z ${OBSOLETE_ON} ] || [ -z ${DELETE_ON} ]; then
                printf "    Setting obsolete/delete dates: %s\n" $NAME
                if [ "$DEBUG" -eq "true" ]; then
                    echo gcloud compute images deprecate $NAME --project $GCP_PROJECT --state=ACTIVE --obsolete-in=${DEPRECATEONDAYS}d --delete-in=${DELETEONDAYS}d --replacement $replacementImage
                    gcloud compute images deprecate $NAME --project $GCP_PROJECT --state=ACTIVE --obsolete-in=${DEPRECATEONDAYS}d --delete-in=${DELETEONDAYS}d --replacement $replacementImage
                else
                    gcloud compute images deprecate $NAME --project $GCP_PROJECT --state=ACTIVE --obsolete-in=${DEPRECATEONDAYS}d --delete-in=${DELETEONDAYS}d --replacement $replacementImage
                fi
            fi
        done

        # Deleting images that exceeded their life expectency.
        for deleteImages in $(gcloud compute images list \
            --project $GCP_PROJECT \
            --filter="name~-golden AND family~$currImageFamily AND creationTimestamp <= -P${DELETEONDAYS}D" \
            --sort-by="~creationTimestamp" \
            --show-deprecated \
            --format="csv[no-heading](name, creationTimestamp.date('%Y-%m-%d'), deprecated.state, deprecated.replacement, deprecated.obsolete, deprecated.deleted)")
        do
            IFS=',' read -r -a deleteImage<<< "$deleteImages"
            NAME="${deleteImage[0]}"
            CREATIONTIMESTAMP="${deleteImage[1]}"
            STATUS="${deleteImage[2]}"
            REPLACEMENT="${deleteImage[3]}"
            OBSOLETE_DATE="${deleteImage[4]}"
            DELETE_DATE="${deleteImage[5]}"
            # if [ "$STATUS" != "OBSOLETE" ]; then
            #     printf "    Obsoleting: %s\n" $NAME
            #     if [ "$DEBUG" -eq "true" ]; then
            #         echo gcloud compute images deprecate $NAME --project $GCP_PROJECT --state=OBSOLETE --obsolete-on=$OBSOLETE_DATE --delete-on=$DELETE_DATE --replacement=$replacementImage
            #         gcloud compute images deprecate $NAME --project $GCP_PROJECT --state=OBSOLETE --obsolete-on=$OBSOLETE_DATE --delete-on=$DELETE_DATE --replacement=$replacementImage
            #     fi
            # fi
            printf "    Deleting: %s\n" $NAME
            if [ "$DEBUG" -eq "true" ]; then
                echo gcloud compute images delete $NAME --project $GCP_PROJECT --quiet
                gcloud compute images delete $NAME --project $GCP_PROJECT --quiet
            else
                gcloud compute images delete $NAME --project $GCP_PROJECT --quiet
            fi
        done

        # Get images that should be marked as deprecated.
        for deprecateImages in $(gcloud compute images list \
            --project $GCP_PROJECT \
            --filter="name~-golden AND family~$currImageFamily AND creationTimestamp <= -P${DEPRECATEONDAYS}D AND creationTimestamp > -P${DELETEONDAYS}D" \
            --sort-by="~creationTimestamp" \
            --format="csv[no-heading](name, creationTimestamp.date('%Y-%m-%d'), deprecated.state, deprecated.replacement, deprecated.obsolete, deprecated.deleted)")
        do
            IFS=',' read -r -a deprecateImage<<< "$deprecateImages"
            NAME="${deprecateImage[0]}"
            CREATIONTIMESTAMP="${deprecateImage[1]}"
            STATUS="${deprecateImage[2]}"
            REPLACEMENT="${deprecateImage[3]}"
            OBSOLETE_DATE="${deprecateImage[4]}"
            DELETE_DATE="${deprecateImage[5]}"
            printf "    Deprecating: %s\n" $NAME
            if [ "$STATUS" != "DEPRECATED" ]; then
                if [ "$DEBUG" -eq "true" ]; then
                    echo gcloud compute images deprecate $NAME --project $GCP_PROJECT --state=DEPRECATED --obsolete-on=$OBSOLETE_DATE --delete-on=$DELETE_DATE --replacement=$REPLACEMENT
                    gcloud compute images deprecate $NAME --project $GCP_PROJECT --state=DEPRECATED --obsolete-on=$OBSOLETE_DATE --delete-on=$DELETE_DATE --replacement=$REPLACEMENT
                else
                    gcloud compute images deprecate $NAME --project $GCP_PROJECT --state=DEPRECATED --obsolete-on=$OBSOLETE_DATE --delete-on=$DELETE_DATE --replacement=$REPLACEMENT
                fi
            fi
        done
  
        # Get all iamges; and update to the latest replacement image.
        for allImages in $(gcloud compute images list \
            --project $GCP_PROJECT \
            --filter="name~-golden AND family~$currImageFamily" \
            --sort-by="~creationTimestamp" \
            --show-deprecated \
            --format="csv[no-heading](name, creationTimestamp.date('%Y-%m-%d'), deprecated.state, deprecated.replacement, deprecated.obsolete, deprecated.deleted)")
        do
            IFS=',' read -r -a image<<< "$allImages"
            NAME="${image[0]}"
            CREATIONTIMESTAMP="${image[1]}"
            STATUS="${image[2]}"
            REPLACEMENT="${image[3]}"
            OBSOLETE_DATE="${image[4]}"
            DELETE_DATE="${image[5]}"
            if [ "$REPLACEMENT" != "${replacementImage}" ]; then
                printf "    Updating replacement image: %s\n" $NAME
                if [ "$DEBUG" -eq "true" ]; then
                    echo gcloud compute images deprecate $NAME --project $GCP_PROJECT --state=$STATUS --obsolete-on=$OBSOLETE_DATE --delete-on=$DELETE_DATE --replacement=$replacementImage
                    gcloud compute images deprecate $NAME --project $GCP_PROJECT --state=$STATUS --obsolete-on=$OBSOLETE_DATE --delete-on=$DELETE_DATE --replacement=$replacementImage
                else
                    gcloud compute images deprecate $NAME --project $GCP_PROJECT --state=$STATUS --obsolete-on=$OBSOLETE_DATE --delete-on=$DELETE_DATE --replacement=$replacementImage
                fi
            fi
        done

        ## Report on Current Image status for this family
        printf "\n\n"
        gcloud compute images list \
            --project $GCP_PROJECT \
            --filter="name~-golden AND family~$currImageFamily" \
            --sort-by="~creationTimestamp" \
            --show-deprecated \
            --format="table[box,title='$currImageFamily Images'](name, deprecated.state, creationTimestamp.date('%Y-%m-%d'), deprecated.obsolete.date('%Y-%m-%d'), deprecated.deleted.date('%Y-%m-%d'), deprecated.replacement)"
        printf "\n\n"
    fi
done <supportedImageFamilies.txt