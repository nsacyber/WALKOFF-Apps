from apps import App, action
from os import listdir, walk
from os.path import isfile, join
from watson_developer_cloud import VisualRecognitionV3 as vr
import json
import sys


class Main(App):
    def __init__(self, name=None, device=None, context=None):
        App.__init__(self, name, device, context)
        self.engine = vr('2018-07-10', iam_apikey=self.device.get_encrypted_field('key'))
        self.jString = ''

    @action
    def detect_faces_from_local_file(self, path, recursive):
        self.jString = json.dumps(self.face_detection(path, None, recursive))
        return "Success"

    @action
    def classify_from_local_file(self, path, recursive):
        self.jString = json.dumps(self.classify_images(path, None, recursive))
        return "Success"

    @action
    def classify_food_from_local_file(self, path, recursive):
        self.jString = json.dumps(self.classify_images(path, "food", recursive))
        return "Success"

    @action
    def classify_explicit_from_local_file(self, path, recursive):
        self.jString = json.dumps(self.classify_images(path, "explicit", recursive))
        return "Success"

    @action
    def generate_report(self, path, keywords):
        #Setup file and load json obj
        keywordList = keywords.split()
        try:
            f = open(path, 'w')
            jsonInfo = json.loads(self.jString)
            f.write('{0:20s} {1:18s} {2:18s} {3:20s} {4:6s}\n'.format('File Name', 'Source','Destination','Description', 'Score'))
            f.write('-------------------------------------------------------------------------------------\n')

            #Parse and extract json info
            for x in range(0, len(jsonInfo), 2):
                filePath = jsonInfo[x].split('/')
                fileName = filePath[len(filePath) - 1]
                source = filePath[len(filePath) - 3]
                destination = filePath[len(filePath) - 2]
                if(jsonInfo[x+1]['status_code'] == 200): #Status OK
                    imageDescription = jsonInfo[x+1]['result']['images'][0]['classifiers'][0]['classes'][0]['class']
                    watsonScore = jsonInfo[x+1]['result']['images'][0]['classifiers'][0]['classes'][0]['score']
                    nsfwScore = self.calculate_score(keywordList, imageDescription, watsonScore)
                    f.write('{0:20s} {1:18s} {2:18s} {3:20s} {4:1.0f}'.format(fileName[0:18], source, destination, imageDescription, nsfwScore))
                    if(nsfwScore > 3): #Suspicious image
                        f.write(" ***")
                else: #Status ERROR
                    f.write('{0:20s} {1:18s} {2:18s} {3:20s} {4:16s}'.format(fileName[0:18], source, destination, "WATSON API ERROR", "WATSON API ERROR"))
                f.write('\n\n')
        except IOError as e: #Could not open report file
            return "Check Path. I/O error({0}): {1}".format(e.errno, e.strerror)

        return "Success"

    # helper method to call work_images with classify function
    def classify_images(self, path, class_id, recursive):
        images = self.ret_images(path, recursive)
        return self.work_images(class_id, self.engine.classify, images)

    # helper method to call work_images with detect_faces function
    def face_detection(self, path, class_id, recursive):
        images = self.ret_images(path, recursive)
        return self.work_images(class_id, self.engine.detect_faces, images)

    # returns paths of all images in a directory or of all images in a directory and subdirectories
    def ret_images(self, path, recursive):
        images = []
        if not recursive:
            files = [f for f in listdir(path) if isfile(join(path, f))]
            for name in files:
                if name.endswith(".png"):
                    images.append(join(path, name))
        else:
            for path, subdirs, files in walk(path):
                for name in files:
                    if name.endswith(".png"):
                        images.append(join(path, name))
        return images

    # opens up each image and performs the specified Watson API call on it (classify, detect_faces)
    def work_images(self, class_id, action, images):
        results = []
        for img in images:
            with open(img, "rb") as image:
                result = action(images_file=image, classifier_ids=class_id)
            results.append(img)
            results.append(json.loads(str(result)))
        return results

    #Function that calculates image score based on Watson's results
    def calculate_score(self, keywords, desc, percentage):
        #if('banana' in desc):
        max = 0
        for s in keywords:
            if (s in desc) and (max < (percentage / .20)):
                max = (percentage / .20)
        return max
