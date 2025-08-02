import logging
import typer
from cloudlogin.aws.awslogin import AWSLogin
from cloudlogin.exceptions import Unauthorized
from types import SimpleNamespace

app = typer.Typer()
logger = logging.getLogger()


@app.callback()
def main(
    ctx: typer.Context,
    debug: bool = typer.Option(False, "--debug", help="Enable debug"),
):
    if debug:
        logging.basicConfig(
            level=logging.DEBUG,
            format="[%(levelname)s] %(message)s",
            handlers=[logging.StreamHandler()],
        )
    else:
        logging.basicConfig(level=logging.WARNING)

    ctx.obj = SimpleNamespace(debug=debug)


@app.command()
def aws(
    aws_profile: str = typer.Option(
        None, "--aws-profile", envvar="AWS_PROFILE", help="AWS profile"
    ),
):
    try:
        if aws_profile is not None:
            logger.debug(f"AWS Profile: {aws_profile}")
        login = AWSLogin(profile=aws_profile)
        typer.echo(f"Logged in to AWS account {login.account_id}")
    except Unauthorized as err:
        typer.echo(f"Unauthorized: {err}")
        raise typer.Exit(code=1)
    except Exception as err:
        typer.echo(f"AWS error: {err}")
        raise typer.Exit(code=2)


if __name__ == "__main__":
    app()
