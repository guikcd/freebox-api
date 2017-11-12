from session import Session
from lan import Lan
from igd import Igd

if __name__ == "__main__":
	#session = Session(debug=True)
	session = Session()
        session.login()
        lan = Lan(session)
	infos = lan.get_lan_info()
	print(infos)
	igd = Igd(session)
	redirections = igd.get_redirections()
        print(redirections)
