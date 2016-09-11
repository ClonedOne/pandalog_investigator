from cli.PandalogInvestigatorApp import PandalogInvestigatorApp


def main():
    with PandalogInvestigatorApp() as app:
        app.setup()
        app.config.parse_file('config.conf')
        app.run()


if __name__ == '__main__':
    main()