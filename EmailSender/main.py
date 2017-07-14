from apps import App, action
import smtplib
import email.utils
from email.mime.text import MIMEText

class Main(App):
    def __init__(self, name=None, device=None):
        App.__init__(self, name, device)
        self._device = self.get_device()
        self.server = smtplib.SMTP_SSL('{0}:{1}'.format(self._device.ip, self._device.port))

        try:
            self.server.set_debuglevel(True)
            self.server.ehlo()
            if self.server.has_extn('STARTTLS'):
                self.server.starttls()
                self.server.ehlo()  # re-identify ourselves over TLS connection
            self.server.login(self._device.username, self._device.get_password())
        except Exception as e:
            print(e)
            print('shutting down')
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