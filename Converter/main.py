from apps import App, action
from PIL import Image
import logging
import os

logger = logging.getLogger(__name__)


@action
def convert_image(input_file, output_file):
    """Converts images from one file type to another

    Arguments:
    input_file -- the file path to be converted from
    output_file -- the file path to the new file

    Note: 
    List of supported formats: https://pillow.readthedocs.io/en/5.3.x/handbook/image-file-formats.html
    """
    if input_file != output_file:
        try:
            Image.open(input_file).save(output_file)
        except IOError:
            return ('Failed to convert ' + input_file + ' to ' + output_file), 'FailedToConvert'
        except ValueError:
            return ('Failed to convert ' + input_file + ' to ' + output_file + '. Check suppprted file types.'), 'FailedToConvert'

    return output_file, 'Success'


@action
def convert_image_batch(input_dir, output_type, sub_directories):
    """Converts all images from their original file type to a specified type calls 
    convert_image for each file. Outputs the new file to the same directory as the
    original file. Tries to convert every file, will only convert supported formats

    Arguments:
    input_dir -- the directory path to convert
    output_type -- the type to convert to ('PNG', 'JPG', etc.)
    sub_directories -- boolean to determine if all sub dir will be explored

    Note: 
    List of supported formats: https://pillow.readthedocs.io/en/5.3.x/handbook/image-file-formats.html
    """
    successful_converts = 0
    if(sub_directories):
        for root, dirs, files in os.walk(input_dir):
            for name in files:
                fp = os.path.join(root, name)  # file path
                output_name = fp[0:(fp.rfind('.') + 1)] + output_type

                if (convert_image(fp, output_name).status == 'Success'):
                    successful_converts += 1
    else:
        for entry in os.scandir(input_dir):
            if entry.is_file():
                output_name = entry.path[0:(entry.name.rfind('.') + 1)] + output_type

                if (convert_image(entry.path, output_name).status == 'Success'):
                    successful_converts += 1
    
    # Make sure at least one file gets converted, if not it's a failure
    if successful_converts > 0:
        return input_dir, 'Success'
    else:
        return input_dir, 'FailedToConvert'