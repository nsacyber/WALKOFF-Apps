from apps import App, action
import splunklib.client as client


class Main(App):
    def __init__(self, name, device, context):
        App.__init__(self, name, device, context)
        self.service = client.connect(host=self.device_fields['ip'], port=self.device_fields['port'],
                                      username=self.device_fields['username'],
                                      password=self.device.get_encrypted_field('password'))
        self.kwargs_create = {}
        self.kwargs_results = {"output_mode": "json"}

    @action
    def set_create_args(self, key, value):
        self.kwargs_create[key] = value

    @action
    def set_results_args(self, key, value):
        self.kwargs_results[key] = value

    @action
    def clear_create_args(self):
        self.kwargs_create.clear()

    @action
    def clear_results_args(self):
        self.kwargs_results.clear()

    @action
    def search(self, query):

        if not query.startswith('search'):
            query = "search " + query

        job = self.service.jobs.create(query, **self.kwargs_create)

        while True:
            while not job.is_ready():
                pass
            if job['isDone'] == '1':
                break

        res = job.results(**self.kwargs_results)

        results = res.read()

        job.cancel()

        return results

    def shutdown(self):
        return
