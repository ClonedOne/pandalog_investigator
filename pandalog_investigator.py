from cli.PandalogInvestigatorApp import PandalogInvestigatorApp


def main():
    with PandalogInvestigatorApp() as app:
        app.setup()
        app.config.parse_file('config.conf')
        app.run()

        data = app.config.get('pandaloginvestigator', 'foo')

        print 'good' if data == u'bar' else 'bad'

if __name__ == '__main__':
    main()