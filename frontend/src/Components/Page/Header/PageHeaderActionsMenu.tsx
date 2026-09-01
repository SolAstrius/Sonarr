import React, { useCallback } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import AppState from 'App/State/AppState';
import Icon from 'Components/Icon';
import Menu from 'Components/Menu/Menu';
import MenuButton from 'Components/Menu/MenuButton';
import MenuContent from 'Components/Menu/MenuContent';
import MenuItem from 'Components/Menu/MenuItem';
import MenuItemSeparator from 'Components/Menu/MenuItemSeparator';
import useApiQuery from 'Helpers/Hooks/useApiQuery';
import { align, icons, kinds } from 'Helpers/Props';
import { restart, shutdown } from 'Store/Actions/systemActions';
import translate from 'Utilities/String/translate';
import styles from './PageHeaderActionsMenu.css';

interface User {
  authenticationMethod: string;
  isAuthenticated: boolean;
  username?: string;
  name?: string;
  email?: string;
  avatar?: string;
  groups?: string[];
}

interface PageHeaderActionsMenuProps {
  onKeyboardShortcutsPress(): void;
}

function PageHeaderActionsMenu(props: PageHeaderActionsMenuProps) {
  const { onKeyboardShortcutsPress } = props;

  const dispatch = useDispatch();

  const { authentication, isDocker } = useSelector(
    (state: AppState) => state.system.status.item
  );

  const signedIn = authentication === 'forms' || authentication === 'oidc';

  const { data: user } = useApiQuery<User>({ url: '/user' });

  const handleRestartPress = useCallback(() => {
    dispatch(restart());
  }, [dispatch]);

  const handleShutdownPress = useCallback(() => {
    dispatch(shutdown());
  }, [dispatch]);

  const showUser = signedIn && user?.isAuthenticated;

  return (
    <div>
      <Menu alignMenu={align.RIGHT}>
        <MenuButton className={styles.menuButton} aria-label="Menu Button">
          <Icon name={icons.INTERACTIVE} title={translate('Menu')} />
        </MenuButton>

        <MenuContent>
          {showUser ? (
            <>
              <div className={styles.user}>
                {user?.avatar ? (
                  <img className={styles.userAvatar} src={user.avatar} alt="" />
                ) : (
                  <Icon className={styles.userAvatarIcon} name={icons.INTERACTIVE} />
                )}

                <div className={styles.userDetails}>
                  <div className={styles.userName}>
                    {user?.name || user?.username}
                  </div>

                  {user?.email ? (
                    <div className={styles.userSecondary}>{user.email}</div>
                  ) : null}

                  {user?.groups?.length ? (
                    <div className={styles.userGroups}>
                      {user.groups.map((group) => (
                        <span key={group} className={styles.userGroup}>
                          {group}
                        </span>
                      ))}
                    </div>
                  ) : null}
                </div>
              </div>

              <MenuItemSeparator />
            </>
          ) : null}

          <MenuItem onPress={onKeyboardShortcutsPress}>
            <Icon className={styles.itemIcon} name={icons.KEYBOARD} />
            {translate('KeyboardShortcuts')}
          </MenuItem>

          {isDocker ? null : (
            <>
              <MenuItemSeparator />

              <MenuItem onPress={handleRestartPress}>
                <Icon className={styles.itemIcon} name={icons.RESTART} />
                {translate('Restart')}
              </MenuItem>

              <MenuItem onPress={handleShutdownPress}>
                <Icon
                  className={styles.itemIcon}
                  name={icons.SHUTDOWN}
                  kind={kinds.DANGER}
                />
                {translate('Shutdown')}
              </MenuItem>
            </>
          )}

          {signedIn ? (
            <>
              <MenuItemSeparator />

              <MenuItem to={`${window.Sonarr.urlBase}/logout`} noRouter={true}>
                <Icon className={styles.itemIcon} name={icons.LOGOUT} />
                {translate('Logout')}
              </MenuItem>
            </>
          ) : null}
        </MenuContent>
      </Menu>
    </div>
  );
}

export default PageHeaderActionsMenu;
