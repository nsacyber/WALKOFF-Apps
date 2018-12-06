from apps import App, action
import smtplib
import email.utils
from email.mime.text import MIMEText


class Main(App):
    def __init__(self, name, device, context):
        App.__init__(self, name, device, context)
        self.server = smtplib.SMTP('{0}:{1}'.format(self.device_fields['ip'], self.device_fields['port']))

        try:
            self.server.set_debuglevel(False)
            self.server.ehlo()
            if self.server.has_extn('STARTTLS'):
                self.server.starttls()
                self.server.ehlo()  # re-identify ourselves over TLS connection
            self.server.login(self.device_fields['username'], self.device.get_encrypted_field('password'))
        except Exception as e:
            self.shutdown()

    @action
    def send_email(self, sender, receivers, subject, message, html, sender_name):
        message_format = 'html' if html else 'plain'
        msg = MIMEText(message, message_format)
        msg.set_unixfrom('author')
        msg['To'] = email.utils.formataddr(('Recipient', receivers))
        msg['From'] = email.utils.formataddr((sender_name, sender))
        msg['Subject'] = subject
        self.server.sendmail(sender, receivers, msg.as_string())
        return 'success'

    def shutdown(self):
        self.server.quit()
